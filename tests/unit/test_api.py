import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
import json
import sys
import os

# Add the app directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from app.main import app
from app.models import Finding
import uuid
from datetime import datetime


class TestAPI:
    """Test FastAPI endpoints"""

    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)

    @pytest.fixture
    def mock_db_session(self):
        """Mock database session"""
        session = AsyncMock()
        session.execute.return_value = AsyncMock()
        session.add.return_value = None
        session.commit.return_value = None
        session.refresh.return_value = None
        return session

    def test_root_endpoint(self, client):
        """Test root endpoint returns service info"""
        response = client.get("/")
        assert response.status_code == 200
        
        data = response.json()
        assert data["service"] == "CloudSentry"
        assert data["version"] == "1.0.0"
        assert data["status"] == "running"
        assert "environment" in data
        assert "docs" in data

    def test_health_endpoint_success(self, client, mock_db_session, mock_redis):
        """Test health endpoint with healthy services"""
        with patch('app.main.get_db') as mock_get_db, \
             patch('redis.Redis.from_url') as mock_redis_client:
            
            mock_get_db.return_value = mock_db_session
            mock_redis_instance = AsyncMock()
            mock_redis_instance.ping.return_value = True
            mock_redis_instance.close.return_value = None
            mock_redis_client.return_value = mock_redis_instance
            
            response = client.get("/health")
            assert response.status_code == 200
            
            data = response.json()
            assert data["status"] == "healthy"
            assert data["components"]["database"] == "healthy"
            assert data["components"]["redis"] == "healthy"
            assert "timestamp" in data

    def test_health_endpoint_database_failure(self, client, mock_db_session, mock_redis):
        """Test health endpoint with database failure"""
        with patch('app.main.get_db') as mock_get_db, \
             patch('redis.Redis.from_url') as mock_redis_client:
            
            # Mock database failure
            mock_db_session.execute.side_effect = Exception("Database connection failed")
            mock_get_db.return_value = mock_db_session
            
            mock_redis_instance = AsyncMock()
            mock_redis_instance.ping.return_value = True
            mock_redis_instance.close.return_value = None
            mock_redis_client.return_value = mock_redis_instance
            
            response = client.get("/health")
            assert response.status_code == 200
            
            data = response.json()
            assert data["status"] == "unhealthy"
            assert "unhealthy" in data["components"]["database"]

    def test_metrics_endpoint(self, client):
        """Test metrics endpoint"""
        response = client.get("/metrics")
        assert response.status_code == 200
        
        data = response.json()
        assert "message" in data

    def test_cors_headers(self, client):
        """Test CORS headers are present"""
        response = client.options("/health")
        assert response.status_code == 200
        
        # Check for CORS headers
        assert "access-control-allow-origin" in response.headers

    def test_security_headers(self, client):
        """Test security headers are present"""
        response = client.get("/")
        assert response.status_code == 200
        
        headers = response.headers
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("X-XSS-Protection") == "1; mode=block"
        assert "Strict-Transport-Security" in headers
        assert "Content-Security-Policy" in headers

    @patch('app.main.get_settings')
    def test_production_docs_disabled(self, mock_settings, client):
        """Test that docs are disabled in production"""
        mock_settings.return_value.allowed_hosts = ["example.com"]
        
        with patch('os.getenv', return_value="production"):
            # Recreate app with production settings
            from app.main import app
            production_client = TestClient(app)
            
            response = production_client.get("/api/docs")
            assert response.status_code == 404

    def test_rate_limiting_headers(self, client):
        """Test rate limiting functionality"""
        # This test would require more complex setup to properly test rate limiting
        # For now, just ensure the endpoint exists
        response = client.get("/")
        assert response.status_code == 200

    def test_websocket_endpoint_exists(self, client):
        """Test that WebSocket endpoint is configured"""
        # WebSocket endpoints can't be easily tested with TestClient
        # but we can verify the router is included
        from app.main import app
        routes = [route.path for route in app.routes]
        assert any("ws" in route for route in routes)

    def test_api_router_included(self, client):
        """Test that API router is properly included"""
        from app.main import app
        routes = [route.path for route in app.routes]
        assert any("/api/v1" in route for route in routes)

    def test_error_handling(self, client):
        """Test error handling for invalid endpoints"""
        response = client.get("/nonexistent-endpoint")
        assert response.status_code == 404

    def test_method_not_allowed(self, client):
        """Test method not allowed handling"""
        response = client.put("/health")
        # FastAPI returns 405 for method not allowed
        assert response.status_code in [405, 404]
