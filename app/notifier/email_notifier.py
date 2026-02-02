import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Any

from app.config import get_settings

logger = logging.getLogger(__name__)

class EmailNotifier:
    """Email notification system"""
    
    def __init__(self):
        self.settings = get_settings()
        self.smtp_host = self.settings.smtp_host
        self.smtp_port = self.settings.smtp_port
        self.smtp_user = self.settings.smtp_user
        self.smtp_password = self.settings.smtp_password
        self.from_email = self.settings.notification_email
    
    async def send_finding_notification(self, finding: Dict[str, Any], recipients: List[str]):
        """Send email notification for a security finding"""
        if not recipients:
            logger.warning("No recipients specified for email notification")
            return
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[CloudSentry] {finding['severity']} severity finding: {finding['rule_id']}"
            msg['From'] = self.from_email
            msg['To'] = ', '.join(recipients)
            
            # Create HTML content
            html = f"""
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; }}
                    .severity-critical {{ color: #ff0000; font-weight: bold; }}
                    .severity-high {{ color: #ff6b00; font-weight: bold; }}
                    .severity-medium {{ color: #ffd000; }}
                    .severity-low {{ color: #00c853; }}
                    .card {{ border: 1px solid #ddd; padding: 20px; margin: 20px 0; border-radius: 5px; }}
                    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 3px; color: white; font-size: 12px; }}
                </style>
            </head>
            <body>
                <h2>CloudSentry Security Finding</h2>
                
                <div class="card">
                    <h3 class="severity-{finding['severity'].lower()}">
                        {finding['severity']}: {finding.get('description', finding['rule_id'])}
                    </h3>
                    
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Resource:</strong></td>
                            <td style="padding: 8px; border-bottom: 1px solid #eee;">{finding['resource_id']} ({finding['resource_type']})</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Account:</strong></td>
                            <td style="padding: 8px; border-bottom: 1px solid #eee;">{finding.get('account_id', 'N/A')}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Region:</strong></td>
                            <td style="padding: 8px; border-bottom: 1px solid #eee;">{finding.get('region', 'N/A')}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Time:</strong></td>
                            <td style="padding: 8px; border-bottom: 1px solid #eee;">{finding['timestamp']}</td>
                        </tr>
                    </table>
                    
                    <h4 style="margin-top: 20px;">Remediation Steps:</h4>
                    <p>{finding.get('remediation_steps', 'No remediation steps provided.')}</p>
                    
                    <p style="margin-top: 20px; font-size: 12px; color: #666;">
                        This finding was detected by CloudSentry. Please investigate and take appropriate action.
                    </p>
                </div>
                
                <p style="color: #666; font-size: 12px; margin-top: 30px;">
                    To view this finding in the dashboard or update its status, visit your CloudSentry instance.
                </p>
            </body>
            </html>
            """
            
            text = f"""
            CloudSentry Security Finding
            ============================
            
            Severity: {finding['severity']}
            Rule: {finding['rule_id']}
            Resource: {finding['resource_id']} ({finding['resource_type']})
            Account: {finding.get('account_id', 'N/A')}
            Region: {finding.get('region', 'N/A')}
            Time: {finding['timestamp']}
            
            Remediation:
            {finding.get('remediation_steps', 'No remediation steps provided.')}
            """
            
            # Attach parts
            msg.attach(MIMEText(text, 'plain'))
            msg.attach(MIMEText(html, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            logger.info(f"Email notification sent to {len(recipients)} recipients")
            
        except Exception as e:
            logger.error(f"Error sending email notification: {e}")
    
    async def send_audit_completion_notification(self, audit_result: Dict[str, Any], recipients: List[str]):
        """Send email notification for audit completion"""
        if not recipients:
            return
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[CloudSentry] Audit {audit_result['status']}: {audit_result['audit_type']} audit"
            msg['From'] = self.from_email
            msg['To'] = ', '.join(recipients)
            
            html = f"""
            <html>
            <body>
                <h2>CloudSentry Audit Complete</h2>
                <p>Audit {audit_result['id']} has {audit_result['status'].lower()}.</p>
                <p><strong>Type:</strong> {audit_result['audit_type']}</p>
                <p><strong>Findings:</strong> {audit_result.get('findings_count', 0)}</p>
                <p><strong>Duration:</strong> {audit_result.get('duration', 'N/A')}</p>
                {f'<p><strong>Error:</strong> {audit_result["error_message"]}</p>' if audit_result.get('error_message') else ''}
            </body>
            </html>
            """
            
            msg.attach(MIMEText(html, 'html'))
            
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
        except Exception as e:
            logger.error(f"Error sending audit completion email: {e}")