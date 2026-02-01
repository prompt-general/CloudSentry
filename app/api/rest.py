from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, and_
from sqlalchemy.orm import selectinload
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import logging

from app.database import get_db
from app.models import Finding, Event, RuleMetadata, AuditLog
from app.config import get_settings

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/findings", response_model=List[Dict[str, Any]])
async def get_findings(
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None, regex="^(LOW|MEDIUM|HIGH|CRITICAL)$"),
    resource_type: Optional[str] = None,
    account_id: Optional[str] = None,
    region: Optional[str] = None,
    status: Optional[str] = Query(None, regex="^(OPEN|IN_PROGRESS|RESOLVED|SUPPRESSED)$"),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    rule_id: Optional[str] = None,
    search: Optional[str] = None
):
    """
    Get security findings with filtering options
    """
    try:
        query = select(Finding)
        
        # Apply filters
        filters = []
        
        if severity:
            filters.append(Finding.severity == severity)
        if resource_type:
            filters.append(Finding.resource_type == resource_type)
        if account_id:
            filters.append(Finding.account_id == account_id)
        if region:
            filters.append(Finding.region == region)
        if status:
            filters.append(Finding.status == status)
        if rule_id:
            filters.append(Finding.rule_id == rule_id)
        if start_date:
            filters.append(Finding.timestamp >= start_date)
        if end_date:
            filters.append(Finding.timestamp <= end_date)
        if search:
            filters.append(Finding.resource_id.ilike(f"%{search}%"))
        
        if filters:
            query = query.where(and_(*filters))
        
        # Order by timestamp (newest first)
        query = query.order_by(desc(Finding.timestamp))
        
        # Apply pagination
        query = query.offset(skip).limit(limit)
        
        result = await db.execute(query)
        findings = result.scalars().all()
        
        return [finding.to_dict() for finding in findings]
        
    except Exception as e:
        logger.error(f"Error fetching findings: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error fetching findings"
        )


@router.get("/findings/{finding_id}", response_model=Dict[str, Any])
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get a specific finding by ID
    """
    try:
        query = select(Finding).where(Finding.id == finding_id)
        result = await db.execute(query)
        finding = result.scalar_one_or_none()
        
        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found"
            )
        
        return finding.to_dict()
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching finding {finding_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error fetching finding"
        )


@router.put("/findings/{finding_id}", response_model=Dict[str, Any])
async def update_finding(
    finding_id: str,
    update_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db)
):
    """
    Update a finding (e.g., change status)
    """
    try:
        query = select(Finding).where(Finding.id == finding_id)
        result = await db.execute(query)
        finding = result.scalar_one_or_none()
        
        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found"
            )
        
        # Update allowed fields
        allowed_fields = ['status', 'remediation_steps']
        for field in allowed_fields:
            if field in update_data:
                setattr(finding, field, update_data[field])
        
        await db.commit()
        
        return finding.to_dict()
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error updating finding {finding_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error updating finding"
        )


@router.delete("/findings/{finding_id}")
async def delete_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Delete a finding (admin only)
    """
    try:
        query = select(Finding).where(Finding.id == finding_id)
        result = await db.execute(query)
        finding = result.scalar_one_or_none()
        
        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found"
            )
        
        await db.delete(finding)
        await db.commit()
        
        return {"message": "Finding deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error deleting finding {finding_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error deleting finding"
        )


@router.get("/findings/stats/summary")
async def get_findings_summary(
    db: AsyncSession = Depends(get_db),
    account_id: Optional[str] = None,
    time_range: Optional[str] = Query("24h", regex="^(24h|7d|30d|all)$")
):
    """
    Get summary statistics for findings
    """
    try:
        # Calculate time range
        now = datetime.utcnow()
        if time_range == "24h":
            start_time = now - timedelta(hours=24)
        elif time_range == "7d":
            start_time = now - timedelta(days=7)
        elif time_range == "30d":
            start_time = now - timedelta(days=30)
        else:
            start_time = None
        
        # Build base query
        query = select(Finding)
        if start_time:
            query = query.where(Finding.timestamp >= start_time)
        if account_id:
            query = query.where(Finding.account_id == account_id)
        
        # Execute count queries
        total_query = select(func.count(Finding.id)).select_from(Finding)
        if start_time:
            total_query = total_query.where(Finding.timestamp >= start_time)
        if account_id:
            total_query = total_query.where(Finding.account_id == account_id)
        
        total_result = await db.execute(total_query)
        total = total_result.scalar()
        
        # Count by severity
        severity_query = select(
            Finding.severity,
            func.count(Finding.id).label('count')
        )
        
        if start_time:
            severity_query = severity_query.where(Finding.timestamp >= start_time)
        if account_id:
            severity_query = severity_query.where(Finding.account_id == account_id)
        
        severity_query = severity_query.group_by(Finding.severity)
        severity_result = await db.execute(severity_query)
        severity_counts = severity_result.all()
        
        # Count by status
        status_query = select(
            Finding.status,
            func.count(Finding.id).label('count')
        )
        
        if start_time:
            status_query = status_query.where(Finding.timestamp >= start_time)
        if account_id:
            status_query = status_query.where(Finding.account_id == account_id)
        
        status_query = status_query.group_by(Finding.status)
        status_result = await db.execute(status_query)
        status_counts = status_result.all()
        
        # Count by resource type
        resource_query = select(
            Finding.resource_type,
            func.count(Finding.id).label('count')
        )
        
        if start_time:
            resource_query = resource_query.where(Finding.timestamp >= start_time)
        if account_id:
            resource_query = resource_query.where(Finding.account_id == account_id)
        
        resource_query = resource_query.group_by(Finding.resource_type)
        resource_result = await db.execute(resource_query)
        resource_counts = resource_result.all()
        
        return {
            "total": total,
            "by_severity": {s.severity: s.count for s in severity_counts},
            "by_status": {s.status: s.count for s in status_counts},
            "by_resource_type": {r.resource_type: r.count for r in resource_counts},
            "time_range": time_range,
            "start_time": start_time.isoformat() if start_time else None
        }
        
    except Exception as e:
        logger.error(f"Error getting findings summary: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error getting summary"
        )


@router.get("/findings/stats/timeline")
async def get_findings_timeline(
    db: AsyncSession = Depends(get_db),
    account_id: Optional[str] = None,
    days: int = Query(7, ge=1, le=90)
):
    """
    Get timeline of findings for charts
    """
    try:
        start_time = datetime.utcnow() - timedelta(days=days)
        
        # Query for daily counts
        timeline_query = """
        SELECT 
            DATE(timestamp) as date,
            severity,
            COUNT(*) as count
        FROM findings
        WHERE timestamp >= :start_time
        """
        
        if account_id:
            timeline_query += " AND account_id = :account_id"
        
        timeline_query += """
        GROUP BY DATE(timestamp), severity
        ORDER BY date ASC
        """
        
        params = {"start_time": start_time}
        if account_id:
            params["account_id"] = account_id
        
        result = await db.execute(timeline_query, params)
        rows = result.all()
        
        # Format for chart
        dates = {}
        for row in rows:
            date_str = row.date.strftime("%Y-%m-%d")
            if date_str not in dates:
                dates[date_str] = {"date": date_str, "total": 0}
            dates[date_str][row.severity] = row.count
            dates[date_str]["total"] += row.count
        
        return list(dates.values())
        
    except Exception as e:
        logger.error(f"Error getting findings timeline: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error getting timeline"
        )


@router.get("/rules", response_model=List[Dict[str, Any]])
async def get_rules(
    db: AsyncSession = Depends(get_db),
    enabled: Optional[bool] = None,
    resource_type: Optional[str] = None
):
    """
    Get all security rules
    """
    try:
        query = select(RuleMetadata)
        
        if enabled is not None:
            query = query.where(RuleMetadata.enabled == enabled)
        if resource_type:
            query = query.where(RuleMetadata.resource_types.contains([resource_type]))
        
        query = query.order_by(RuleMetadata.id)
        result = await db.execute(query)
        rules = result.scalars().all()
        
        return [
            {
                "id": rule.id,
                "description": rule.description,
                "severity": rule.severity,
                "resource_types": rule.resource_types,
                "enabled": rule.enabled,
                "created_at": rule.created_at.isoformat() if rule.created_at else None,
                "updated_at": rule.updated_at.isoformat() if rule.updated_at else None
            }
            for rule in rules
        ]
        
    except Exception as e:
        logger.error(f"Error fetching rules: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error fetching rules"
        )


@router.get("/rules/{rule_id}", response_model=Dict[str, Any])
async def get_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get a specific rule by ID
    """
    try:
        query = select(RuleMetadata).where(RuleMetadata.id == rule_id)
        result = await db.execute(query)
        rule = result.scalar_one_or_none()
        
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Rule not found"
            )
        
        return {
            "id": rule.id,
            "description": rule.description,
            "severity": rule.severity,
            "resource_types": rule.resource_types,
            "enabled": rule.enabled,
            "created_at": rule.created_at.isoformat() if rule.created_at else None,
            "updated_at": rule.updated_at.isoformat() if rule.updated_at else None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching rule {rule_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error fetching rule"
        )


@router.put("/rules/{rule_id}", response_model=Dict[str, Any])
async def update_rule(
    rule_id: str,
    update_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db)
):
    """
    Update a rule (e.g., enable/disable)
    """
    try:
        query = select(RuleMetadata).where(RuleMetadata.id == rule_id)
        result = await db.execute(query)
        rule = result.scalar_one_or_none()
        
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Rule not found"
            )
        
        # Update allowed fields
        if 'enabled' in update_data:
            rule.enabled = update_data['enabled']
        
        rule.updated_at = datetime.utcnow()
        await db.commit()
        
        return {
            "id": rule.id,
            "enabled": rule.enabled,
            "updated_at": rule.updated_at.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error updating rule {rule_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error updating rule"
        )


@router.get("/events", response_model=List[Dict[str, Any]])
async def get_events(
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    event_name: Optional[str] = None,
    resource_type: Optional[str] = None,
    account_id: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None
):
    """
    Get CloudTrail events (for debugging and analysis)
    """
    try:
        query = select(Event)
        
        filters = []
        if event_name:
            filters.append(Event.event_name == event_name)
        if resource_type:
            filters.append(Event.resource_type == resource_type)
        if account_id:
            filters.append(Event.account_id == account_id)
        if start_date:
            filters.append(Event.event_time >= start_date)
        if end_date:
            filters.append(Event.event_time <= end_date)
        
        if filters:
            query = query.where(and_(*filters))
        
        query = query.order_by(desc(Event.event_time)).offset(skip).limit(limit)
        result = await db.execute(query)
        events = result.scalars().all()
        
        return [
            {
                "id": str(event.id),
                "event_id": event.event_id,
                "event_name": event.event_name,
                "event_source": event.event_source,
                "event_time": event.event_time.isoformat() if event.event_time else None,
                "resource_id": event.resource_id,
                "resource_type": event.resource_type,
                "account_id": event.account_id,
                "region": event.region,
                "processed_at": event.processed_at.isoformat() if event.processed_at else None
            }
            for event in events
        ]
        
    except Exception as e:
        logger.error(f"Error fetching events: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error fetching events"
        )


@router.get("/health/detailed")
async def detailed_health_check(
    db: AsyncSession = Depends(get_db)
):
    """
    Detailed health check with component status
    """
    try:
        # Check database
        db_status = "healthy"
        try:
            await db.execute("SELECT 1")
        except Exception as e:
            db_status = f"unhealthy: {str(e)}"
        
        # Get counts
        findings_count = await db.scalar(select(func.count(Finding.id)))
        events_count = await db.scalar(select(func.count(Event.id)))
        rules_count = await db.scalar(select(func.count(RuleMetadata.id)))
        
        # Check Redis (if configured)
        settings = get_settings()
        redis_status = "not_configured"
        try:
            import aioredis
            redis = await aioredis.from_url(settings.redis_url)
            await redis.ping()
            redis_status = "healthy"
            await redis.close()
        except ImportError:
            redis_status = "aioredis_not_installed"
        except Exception as e:
            redis_status = f"unhealthy: {str(e)}"
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "components": {
                "database": db_status,
                "redis": redis_status
            },
            "counts": {
                "findings": findings_count,
                "events": events_count,
                "rules": rules_count
            }
        }
        
    except Exception as e:
        logger.error(f"Error in detailed health check: {e}")
        return {
            "status": "unhealthy",
            "error": str(e)
        }


@router.post("/audits/trigger")
async def trigger_audit(
    audit_type: str = Query("full", regex="^(full|targeted)$"),
    account_id: Optional[str] = None,
    resource_type: Optional[str] = None
):
    """
    Trigger a manual security audit
    """
    try:
        from app.scheduler.audit_scheduler import trigger_manual_audit
        
        audit_id = await trigger_manual_audit(
            audit_type=audit_type,
            account_id=account_id,
            resource_type=resource_type
        )
        
        return {
            "message": "Audit triggered successfully",
            "audit_id": audit_id,
            "audit_type": audit_type,
            "account_id": account_id,
            "resource_type": resource_type
        }
        
    except Exception as e:
        logger.error(f"Error triggering audit: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error triggering audit: {str(e)}"
        )


@router.get("/audits", response_model=List[Dict[str, Any]])
async def get_audits(
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    status: Optional[str] = None,
    audit_type: Optional[str] = None
):
    """
    Get audit history
    """
    try:
        query = select(AuditLog).order_by(desc(AuditLog.start_time))
        
        if status:
            query = query.where(AuditLog.status == status)
        if audit_type:
            query = query.where(AuditLog.audit_type == audit_type)
        
        query = query.offset(skip).limit(limit)
        result = await db.execute(query)
        audits = result.scalars().all()
        
        return [
            {
                "id": str(audit.id),
                "audit_type": audit.audit_type,
                "account_id": audit.account_id,
                "start_time": audit.start_time.isoformat() if audit.start_time else None,
                "end_time": audit.end_time.isoformat() if audit.end_time else None,
                "status": audit.status,
                "findings_count": audit.findings_count,
                "error_message": audit.error_message,
                "created_at": audit.created_at.isoformat() if audit.created_at else None
            }
            for audit in audits
        ]
        
    except Exception as e:
        logger.error(f"Error fetching audits: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error fetching audits"
        )