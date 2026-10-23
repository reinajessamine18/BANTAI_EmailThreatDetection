"""Send password-reset messages through a configured SMTP STARTTLS server."""

from __future__ import annotations

import ssl
import smtplib
from email.message import EmailMessage
from urllib.parse import urlencode

from app.core.config import Settings


def is_configured(settings: Settings) -> bool:
    if not settings.smtp_host or not settings.smtp_sender:
        return False
    if not settings.smtp_username and settings.smtp_password is None:
        return True
    return bool(settings.smtp_username) and bool(
        settings.smtp_password and settings.smtp_password.get_secret_value()
    )


def reset_link(settings: Settings, token: str) -> str:
    return (
        f"{settings.frontend_base_url.rstrip('/')}/reset-password?"
        f"{urlencode({'token': token})}"
    )


def send_password_reset_email(settings: Settings, recipient: str, link: str) -> None:
    if not is_configured(settings):
        raise ValueError("SMTP password reset settings are incomplete.")
    assert settings.smtp_host is not None
    assert settings.smtp_sender is not None
    message = EmailMessage()
    message["Subject"] = "Reset your BANTAI password"
    message["From"] = settings.smtp_sender
    message["To"] = recipient
    message.set_content(
        "A password reset was requested for your BANTAI account.\n\n"
        f"Use this one-time link within {settings.password_reset_token_ttl_minutes} minutes:\n"
        f"{link}\n\n"
        "If you did not request this, you can ignore this email."
    )

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
        smtp.ehlo()
        smtp.starttls(context=ssl.create_default_context())
        smtp.ehlo()
        if settings.smtp_username and settings.smtp_password:
            smtp.login(
                settings.smtp_username,
                settings.smtp_password.get_secret_value(),
            )
        smtp.send_message(message)
