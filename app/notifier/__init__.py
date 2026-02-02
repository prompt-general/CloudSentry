import logging
from typing import Dict, Any, List
from app.config import get_settings
from app.notifier.email_notifier import EmailNotifier
from app.notifier.slack_notifier import SlackNotifier

logger = logging.getLogger(__name__)

class NotificationManager:
    """Manages all notifications"""
    
    def __init__(self):
        self.settings = get_settings()
        self.email_notifier = EmailNotifier()
        self.slack_notifier = SlackNotifier()
        
        # Configure notification recipients
        self.email_recipients = self._parse_email_recipients()
    
    def _parse_email_recipients(self) -> List[str]:
        """Parse email recipients from settings"""
        recipients = []
        if hasattr(self.settings, 'notification_email'):
            recipients.append(self.settings.notification_email)
        
        # Could add more recipients from environment
        return recipients
    
    async def notify_finding(self, finding: Dict[str, Any]):
        """Send notifications for a new finding"""
        # Only notify for high/critical findings
        if finding['severity'] not in ['HIGH', 'CRITICAL']:
            return
        
        logger.info(f"Sending notifications for {finding['severity']} finding: {finding['rule_id']}")
        
        # Send email notification
        if self.email_recipients:
            try:
                await self.email_notifier.send_finding_notification(finding, self.email_recipients)
            except Exception as e:
                logger.error(f"Error sending email notification: {e}")
        
        # Send Slack notification
        try:
            await self.slack_notifier.send_finding_notification(finding)
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
    
    async def notify_audit_completion(self, audit_result: Dict[str, Any]):
        """Send notifications for audit completion"""
        logger.info(f"Sending audit completion notification: {audit_result['id']}")
        
        # Send email
        if self.email_recipients:
            try:
                await self.email_notifier.send_audit_completion_notification(audit_result, self.email_recipients)
            except Exception as e:
                logger.error(f"Error sending audit email: {e}")
        
        # Send Slack
        try:
            await self.slack_notifier.send_audit_completion_notification(audit_result)
        except Exception as e:
            logger.error(f"Error sending audit Slack: {e}")


# Global notification manager
notification_manager = NotificationManager()

async def notify_new_finding(finding: Dict[str, Any]):
    """Notify about a new finding"""
    await notification_manager.notify_finding(finding)

async def notify_audit_result(audit_result: Dict[str, Any]):
    """Notify about audit completion"""
    await notification_manager.notify_audit_completion(audit_result)