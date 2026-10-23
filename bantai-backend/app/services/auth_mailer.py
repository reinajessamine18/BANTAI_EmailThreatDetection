"""Deliver authentication one-time passcodes through SMTP STARTTLS."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

from app.core.config import Settings


def is_configured(settings: Settings) -> bool:
    if not settings.smtp_host or not settings.smtp_sender:
        return False
    if not settings.smtp_username and settings.smtp_password is None:
        return True
    return bool(settings.smtp_username) and bool(
        settings.smtp_password and settings.smtp_password.get_secret_value()
    )


def send_otp_email(
    settings: Settings,
    recipient: str,
    code: str,
    purpose: str,
    expires_in_minutes: int = 10,
) -> None:
    if not is_configured(settings):
        raise ValueError("Authentication email SMTP settings are incomplete.")

    subject, action = {
        "registration": ("Verify your BANTAI email", "verify your email address"),
        "password_reset": ("Your BANTAI password reset code", "reset your password"),
        "google_password_setup": (
            "Set up password sign-in for BANTAI",
            "set up password sign-in",
        ),
    }[purpose]
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_sender
    message["To"] = recipient
    message.set_content(
        f"Use this code to {action}: {code}\n\n"
        f"The code expires in {expires_in_minutes} minutes and can only be used once. "
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
