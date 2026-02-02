import logging
from typing import Dict, Any, List
import json

from app.config import get_settings

logger = logging.getLogger(__name__)

class SlackNotifier:
    """Slack notification system"""
    
    def __init__(self):
        self.settings = get_settings()
        self.webhook_url = self.settings.slack_webhook_url
    
    async def send_finding_notification(self, finding: Dict[str, Any], channel: str = None):
        """Send Slack notification for a security finding"""
        if not self.webhook_url:
            logger.warning("Slack webhook URL not configured")
            return
        
        try:
            import aiohttp
            
            severity_colors = {
                'CRITICAL': '#ff0000',
                'HIGH': '#ff6b00',
                'MEDIUM': '#ffd000',
                'LOW': '#00c853'
            }
            
            # Create Slack message
            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🚨 {finding['severity']} Security Finding Detected"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Rule:*\n{finding['rule_id']}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Severity:*\n{finding['severity']}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Resource:*\n{finding['resource_id']}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Type:*\n{finding['resource_type']}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Account:*\n{finding.get('account_id', 'N/A')}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Region:*\n{finding.get('region', 'N/A')}"
                        }
                    ]
                }
            ]
            
            if finding.get('remediation_steps'):
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Remediation:*\n{finding['remediation_steps']}"
                    }
                })
            
            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Detected at {finding['timestamp']}"
                    }
                ]
            })
            
            payload = {
                "blocks": blocks,
                "attachments": [
                    {
                        "color": severity_colors.get(finding['severity'], '#757575'),
                        "blocks": blocks
                    }
                ]
            }
            
            if channel:
                payload["channel"] = channel
            
            # Send to Slack
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as response:
                    if response.status != 200:
                        logger.error(f"Slack API error: {response.status}")
                    else:
                        logger.info("Slack notification sent")
        
        except ImportError:
            logger.error("aiohttp not installed. Cannot send Slack notification.")
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
    
    async def send_audit_completion_notification(self, audit_result: Dict[str, Any], channel: str = None):
        """Send Slack notification for audit completion"""
        if not self.webhook_url:
            return
        
        try:
            import aiohttp
            
            status_emoji = "✅" if audit_result['status'] == 'COMPLETED' else "❌"
            
            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{status_emoji} Audit {audit_result['status']}"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Type:*\n{audit_result['audit_type']}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Findings:*\n{audit_result.get('findings_count', 0)}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Account:*\n{audit_result.get('account_id', 'N/A')}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Duration:*\n{audit_result.get('duration', 'N/A')}"
                        }
                    ]
                }
            ]
            
            if audit_result.get('error_message'):
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Error:*\n{audit_result['error_message']}"
                    }
                })
            
            payload = {"blocks": blocks}
            if channel:
                payload["channel"] = channel
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as response:
                    if response.status != 200:
                        logger.error(f"Slack API error: {response.status}")
        
        except Exception as e:
            logger.error(f"Error sending Slack audit notification: {e}")