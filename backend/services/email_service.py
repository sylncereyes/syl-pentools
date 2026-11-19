"""
Email service for sending notifications, invites, and reports.
"""
from __future__ import annotations

import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from typing import Optional, List
from pathlib import Path

from core.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    """SMTP-based email service."""

    def __init__(self):
        self.enabled = bool(settings.SMTP_HOST and settings.SMTP_USER and settings.SMTP_PASSWORD)

    def _create_connection(self) -> Optional[smtplib.SMTP]:
        """Create and return SMTP connection."""
        if not self.enabled:
            logger.warning("Email service not configured (missing SMTP settings)")
            return None

        try:
            if settings.SMTP_TLS:
                conn = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
                conn.starttls()
            else:
                conn = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT)

            conn.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            return conn
        except Exception as e:
            logger.error(f"Failed to connect to SMTP server: {e}")
            return None

    def send_email(
        self,
        to: List[str],
        subject: str,
        body_html: str,
        body_text: Optional[str] = None,
        attachments: Optional[List[tuple]] = None,
    ) -> bool:
        """
        Send an email.

        Args:
            to: List of recipient email addresses
            subject: Email subject
            body_html: HTML body
            body_text: Plain text body (optional)
            attachments: List of (filename, content_bytes, mime_type) tuples

        Returns:
            True if sent successfully, False otherwise
        """
        if not self.enabled:
            logger.info("Email service disabled, skipping send")
            return False

        if not to:
            logger.warning("No recipients specified")
            return False

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_FROM
        msg["To"] = ", ".join(to)

        # Add plain text part
        if body_text:
            msg.attach(MIMEText(body_text, "plain"))

        # Add HTML part
        msg.attach(MIMEText(body_html, "html"))

        # Add attachments
        if attachments:
            for filename, content, mime_type in attachments:
                part = MIMEApplication(content, Name=filename)
                part["Content-Disposition"] = f'attachment; filename="{filename}"'
                msg.attach(part)

        conn = self._create_connection()
        if not conn:
            return False

        try:
            conn.sendmail(settings.SMTP_FROM, to, msg.as_string())
            conn.quit()
            logger.info(f"Email sent to {to}: {subject}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            try:
                conn.quit()
            except Exception:
                pass
            return False

    def send_invite_email(
        self,
        to: str,
        inviter_name: str,
        workspace_name: str,
        invite_token: str,
        invite_url: str,
    ) -> bool:
        """Send workspace invitation email."""
        subject = f"Invitation to join {workspace_name} on Pentest Tools"

        body_html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #2c3e50;">Workspace Invitation</h2>
                <p>Hi,</p>
                <p><strong>{inviter_name}</strong> has invited you to join the workspace <strong>{workspace_name}</strong> on Pentest Tools.</p>
                <p>Click the button below to accept the invitation:</p>
                <p style="text-align: center; margin: 30px 0;">
                    <a href="{invite_url}" style="background-color: #3498db; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
                        Accept Invitation
                    </a>
                </p>
                <p>Or copy this link: <a href="{invite_url}">{invite_url}</a></p>
                <p>This invitation expires in 7 days.</p>
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
                <p style="font-size: 12px; color: #888;">
                    If you didn't expect this invitation, you can safely ignore this email.
                </p>
            </div>
        </body>
        </html>
        """

        body_text = f"""
        Workspace Invitation

        Hi,

        {inviter_name} has invited you to join the workspace {workspace_name} on Pentest Tools.

        Accept the invitation: {invite_url}

        This invitation expires in 7 days.

        If you didn't expect this invitation, you can safely ignore this email.
        """

        return self.send_email([to], subject, body_html, body_text)

    def send_report_email(
        self,
        to: List[str],
        report_name: str,
        report_format: str,
        report_bytes: bytes,
        workspace_name: str,
    ) -> bool:
        """Send report as email attachment."""
        subject = f"Report: {report_name} ({report_format.upper()})"

        body_html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #2c3e50;">Report Ready</h2>
                <p>Your report <strong>{report_name}</strong> from workspace <strong>{workspace_name}</strong> is ready.</p>
                <p>The report is attached as a {report_format.upper()} file.</p>
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
                <p style="font-size: 12px; color: #888;">
                    This is an automated message from Pentest Tools.
                </p>
            </div>
        </body>
        </html>
        """

        body_text = f"""
        Report Ready

        Your report {report_name} from workspace {workspace_name} is ready.
        The report is attached as a {report_format.upper()} file.
        """

        return self.send_email(
            to,
            subject,
            body_html,
            body_text,
            attachments=[(f"{report_name}.{report_format}", report_bytes, f"application/{report_format}")]
        )

    def send_scan_notification(
        self,
        to: List[str],
        scan_name: str,
        status: str,
        findings_count: int,
        workspace_name: str,
    ) -> bool:
        """Send scan completion notification."""
        status_colors = {
            "completed": "#27ae60",
            "failed": "#e74c3c",
            "cancelled": "#f39c12",
        }
        color = status_colors.get(status.lower(), "#3498db")

        subject = f"Scan {status.capitalize()}: {scan_name}"

        body_html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #2c3e50;">Scan {status.capitalize()}</h2>
                <p>Scan <strong>{scan_name}</strong> in workspace <strong>{workspace_name}</strong> has {status}.</p>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 4px; margin: 20px 0;">
                    <p><strong>Status:</strong> <span style="color: {color};">{status.capitalize()}</span></p>
                    <p><strong>Findings:</strong> {findings_count}</p>
                </div>
                <p>Log in to Pentest Tools to view the full results.</p>
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
                <p style="font-size: 12px; color: #888;">
                    This is an automated notification from Pentest Tools.
                </p>
            </div>
        </body>
        </html>
        """

        body_text = f"""
        Scan {status.capitalize()}

        Scan {scan_name} in workspace {workspace_name} has {status}.
        Findings: {findings_count}

        Log in to Pentest Tools to view the full results.
        """

        return self.send_email(to, subject, body_html, body_text)


# Global instance
email_service = EmailService()