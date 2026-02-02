from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import time
import logging
import asyncio
from typing import Dict, List
from collections import defaultdict, deque
from threading import Lock

logger = logging.getLogger(__name__)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""
    
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        return response

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Thread-safe rate limiting middleware with optimized cleanup"""
    
    def __init__(self, app, max_requests: int = 100, time_window: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests: Dict[str, deque] = defaultdict(deque)
        self.lock = Lock()
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # 5 minutes
    
    def _cleanup_old_requests(self) -> None:
        """Clean up old requests efficiently"""
        current_time = time.time()
        
        # Only run cleanup periodically
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        with self.lock:
            # Remove old entries for each IP
            for ip in list(self.requests.keys()):
                request_times = self.requests[ip]
                # Remove old requests while keeping recent ones
                while request_times and current_time - request_times[0] >= self.time_window:
                    request_times.popleft()
                
                # Remove empty entries to prevent memory leak
                if not request_times:
                    del self.requests[ip]
            
            self.last_cleanup = current_time
    
    async def dispatch(self, request: Request, call_next) -> Response:
        client_ip = request.client.host
        current_time = time.time()
        
        # Periodic cleanup
        self._cleanup_old_requests()
        
        # Thread-safe rate limit check
        with self.lock:
            request_times = self.requests[client_ip]
            
            # Remove old requests for this IP only
            while request_times and current_time - request_times[0] >= self.time_window:
                request_times.popleft()
            
            # Check rate limit
            if len(request_times) >= self.max_requests:
                raise HTTPException(
                    status_code=429,
                    detail="Too many requests"
                )
            
            # Add current request
            request_times.append(current_time)
        
        return await call_next(request)

class LoggingMiddleware(BaseHTTPMiddleware):
    """Log all requests with timing"""
    
    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.time()
        
        response = await call_next(request)
        
        process_time = time.time() - start_time
        logger.info(
            f"{request.method} {request.url.path} "
            f"Status: {response.status_code} "
            f"Duration: {process_time:.3f}s"
        )
        
        return response
