import time
import asyncio
from functools import wraps
from typing import Dict, Any
import logging
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from fastapi import Request, Response
from starlette.responses import PlainTextResponse

logger = logging.getLogger(__name__)

# Prometheus metrics
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

REQUEST_DURATION = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint']
)

ACTIVE_CONNECTIONS = Gauge(
    'active_connections',
    'Number of active connections'
)

FINDINGS_TOTAL = Counter(
    'cloudsentry_findings_total',
    'Total security findings',
    ['severity', 'account_id', 'rule_id']
)

AUDITS_TOTAL = Counter(
    'cloudsentry_audits_total',
    'Total security audits',
    ['audit_type', 'status']
)

ACCOUNTS_MONITORED = Gauge(
    'cloudsenter_accounts_monitored_total',
    'Number of AWS accounts being monitored'
)

def monitor_performance(func):
    """Decorator to monitor function performance"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            duration = time.time() - start_time
            logger.debug(f"{func.__name__} completed in {duration:.3f}s")
            return result
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"{func.__name__} failed after {duration:.3f}s: {e}")
            raise
    return wrapper

class PerformanceMonitor:
    """Performance monitoring utilities"""
    
    def __init__(self):
        self.metrics: Dict[str, Any] = {}
        self.start_time = time.time()
    
    def record_finding(self, severity: str, account_id: str, rule_id: str):
        """Record a new security finding"""
        FINDINGS_TOTAL.labels(
            severity=severity,
            account_id=account_id,
            rule_id=rule_id
        ).inc()
    
    def record_audit(self, audit_type: str, status: str):
        """Record an audit execution"""
        AUDITS_TOTAL.labels(
            audit_type=audit_type,
            status=status
        ).inc()
    
    def update_accounts_count(self, count: int):
        """Update the number of monitored accounts"""
        ACCOUNTS_MONITORED.set(count)
    
    def get_metrics(self) -> str:
        """Get Prometheus metrics"""
        return generate_latest()

async def metrics_endpoint(request: Request) -> Response:
    """FastAPI endpoint for Prometheus metrics"""
    monitor = PerformanceMonitor()
    return PlainTextResponse(monitor.get_metrics(), media_type="text/plain")

class DatabaseMonitor:
    """Database performance monitoring"""
    
    def __init__(self):
        self.query_count = 0
        self.query_duration_total = 0.0
        self.slow_queries = 0
    
    def record_query(self, duration: float, slow_threshold: float = 1.0):
        """Record database query performance"""
        self.query_count += 1
        self.query_duration_total += duration
        
        if duration > slow_threshold:
            self.slow_queries += 1
            logger.warning(f"Slow query detected: {duration:.3f}s")
    
    def get_stats(self) -> Dict[str, float]:
        """Get database performance statistics"""
        if self.query_count == 0:
            return {
                'query_count': 0,
                'avg_duration': 0.0,
                'slow_queries': 0
            }
        
        return {
            'query_count': self.query_count,
            'avg_duration': self.query_duration_total / self.query_count,
            'slow_queries': self.slow_queries
        }

# Global database monitor instance
db_monitor = DatabaseMonitor()
