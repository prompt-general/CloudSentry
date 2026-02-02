import asyncio
import logging
from celery import Celery
from celery.schedules import crontab

from app.config import get_settings
from app.scheduler.audit_scheduler import scheduler

logger = logging.getLogger(__name__)

settings = get_settings()

# Create Celery app
celery_app = Celery(
    'cloudsentry',
    broker=settings.redis_url,
    backend=settings.redis_url
)

# Configure Celery
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    beat_schedule={
        'full-audit-daily': {
            'task': 'app.scheduler.celery_app.run_full_audit_task',
            'schedule': crontab(hour=2, minute=0),  # Run daily at 2 AM UTC
            'args': (),
        },
        'targeted-audit-hourly': {
            'task': 'app.scheduler.celery_app.run_targeted_audit_task',
            'schedule': crontab(minute=0),  # Run hourly
            'args': (['s3'],),  # Audit S3 buckets hourly
        },
    }
)

@celery_app.task
def run_full_audit_task():
    """Celery task to run full audit"""
    # Run in async context
    asyncio.run(scheduler.run_full_audit())

@celery_app.task
def run_targeted_audit_task(resource_types):
    """Celery task to run targeted audit"""
    # This would run targeted audits on specific resource types
    pass
