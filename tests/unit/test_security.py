import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio
from datetime import datetime, timedelta

from app.security.middleware import (
    SecurityHeadersMiddleware,
    RateLimitMiddleware,
    LoggingMiddleware
)
from fastapi import Request, HTTPException
from starlette.responses import Response


class TestSecurityMiddleware:
    """Test security middleware components"""

    @pytest.fixture
    def mock_request(self):
        """Create mock request"""
        request = MagicMock(spec=Request)
        request.client.host = "192.168.1.100"
        request.method = "GET"
        request.url.path = "/test"
        return request

    @pytest.fixture
    def mock_response(self):
        """Create mock response"""
        response = MagicMock(spec=Response)
        response.headers = {}
        return response

    @pytest.mark.asyncio
    async def test_security_headers_middleware(self, mock_request, mock_response):
        """Test security headers are added"""
        middleware = SecurityHeadersMiddleware(app=None)
        
        mock_call_next = AsyncMock(return_value=mock_response)
        
        response = await middleware.dispatch(mock_request, mock_call_next)
        
        # Check security headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-XSS-Protection"] == "1; mode=block"
        assert "Strict-Transport-Security" in response.headers
        assert "Content-Security-Policy" in response.headers
        assert "Referrer-Policy" in response.headers

    @pytest.mark.asyncio
    async def test_rate_limit_middleware_under_limit(self, mock_request, mock_response):
        """Test rate limiting allows requests under limit"""
        middleware = RateLimitMiddleware(app=None, max_requests=10, time_window=60)
        
        mock_call_next = AsyncMock(return_value=mock_response)
        
        # Make multiple requests under the limit
        for i in range(5):
            response = await middleware.dispatch(mock_request, mock_call_next)
            assert response is not None

    @pytest.mark.asyncio
    async def test_rate_limit_middleware_over_limit(self, mock_request, mock_response):
        """Test rate limiting blocks requests over limit"""
        middleware = RateLimitMiddleware(app=None, max_requests=2, time_window=60)
        
        mock_call_next = AsyncMock(return_value=mock_response)
        
        # Make requests up to the limit
        await middleware.dispatch(mock_request, mock_call_next)
        await middleware.dispatch(mock_request, mock_call_next)
        
        # Next request should be rate limited
        with pytest.raises(HTTPException) as exc_info:
            await middleware.dispatch(mock_request, mock_call_next)
        
        assert exc_info.value.status_code == 429
        assert "Too many requests" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_rate_limit_middleware_time_window(self, mock_request, mock_response):
        """Test rate limiting resets after time window"""
        middleware = RateLimitMiddleware(app=None, max_requests=1, time_window=1)
        
        mock_call_next = AsyncMock(return_value=mock_response)
        
        # Make first request
        await middleware.dispatch(mock_request, mock_call_next)
        
        # Wait for time window to pass
        await asyncio.sleep(1.1)
        
        # Should be able to make another request
        response = await middleware.dispatch(mock_request, mock_call_next)
        assert response is not None

    @pytest.mark.asyncio
    async def test_rate_limit_middleware_different_ips(self, mock_request, mock_response):
        """Test rate limiting is per IP address"""
        middleware = RateLimitMiddleware(app=None, max_requests=1, time_window=60)
        
        mock_call_next = AsyncMock(return_value=mock_response)
        
        # Request from first IP
        await middleware.dispatch(mock_request, mock_call_next)
        
        # Change IP and make another request
        mock_request.client.host = "192.168.1.101"
        response = await middleware.dispatch(mock_request, mock_call_next)
        assert response is not None

    @pytest.mark.asyncio
    async def test_rate_limit_middleware_cleanup(self, mock_request, mock_response):
        """Test rate limiting cleanup of old requests"""
        middleware = RateLimitMiddleware(app=None, max_requests=1, time_window=1)
        
        mock_call_next = AsyncMock(return_value=mock_response)
        
        # Make request to add entry
        await middleware.dispatch(mock_request, mock_call_next)
        
        # Wait for cleanup window
        await asyncio.sleep(1.1)
        
        # Trigger cleanup by making another request from different IP
        mock_request.client.host = "192.168.1.101"
        await middleware.dispatch(mock_request, mock_call_next)
        
        # Original IP should be cleaned up
        assert len(middleware.requests) == 1

    @pytest.mark.asyncio
    async def test_logging_middleware(self, mock_request, mock_response):
        """Test logging middleware logs requests"""
        middleware = LoggingMiddleware(app=None)
        
        mock_call_next = AsyncMock(return_value=mock_response)
        mock_response.status_code = 200
        
        with patch('app.security.middleware.logger.info') as mock_log:
            response = await middleware.dispatch(mock_request, mock_call_next)
            
            # Verify logging was called
            mock_log.assert_called_once()
            log_message = mock_log.call_args[0][0]
            assert "GET /test" in log_message
            assert "Status: 200" in log_message
            assert "Duration:" in log_message

    @pytest.mark.asyncio
    async def test_logging_middleware_timing(self, mock_request, mock_response):
        """Test logging middleware measures request duration"""
        middleware = LoggingMiddleware(app=None)
        
        mock_call_next = AsyncMock(return_value=mock_response)
        mock_response.status_code = 200
        
        with patch('app.security.middleware.logger.info') as mock_log:
            await middleware.dispatch(mock_request, mock_call_next)
            
            log_message = mock_log.call_args[0][0]
            # Should contain timing information
            assert "Duration:" in log_message
            assert "s" in log_message

    @pytest.mark.asyncio
    async def test_rate_limit_thread_safety(self, mock_request, mock_response):
        """Test rate limiting middleware is thread-safe"""
        middleware = RateLimitMiddleware(app=None, max_requests=5, time_window=60)
        
        mock_call_next = AsyncMock(return_value=mock_response)
        
        # Simulate concurrent requests
        tasks = []
        for i in range(3):
            task = asyncio.create_task(middleware.dispatch(mock_request, mock_call_next))
            tasks.append(task)
        
        # All should complete without race conditions
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Should not have any exceptions
        exceptions = [r for r in results if isinstance(r, Exception)]
        assert len(exceptions) == 0

    def test_rate_limit_initialization(self):
        """Test rate limit middleware initialization"""
        middleware = RateLimitMiddleware(app=None, max_requests=100, time_window=60)
        
        assert middleware.max_requests == 100
        assert middleware.time_window == 60
        assert middleware.requests == {}
        assert middleware.cleanup_interval == 300

    @pytest.mark.asyncio
    async def test_middleware_call_next_invocation(self, mock_request, mock_response):
        """Test that call_next is properly invoked"""
        middleware = SecurityHeadersMiddleware(app=None)
        
        mock_call_next = AsyncMock(return_value=mock_response)
        
        await middleware.dispatch(mock_request, mock_call_next)
        
        # Verify call_next was called
        mock_call_next.assert_called_once_with(mock_request)
