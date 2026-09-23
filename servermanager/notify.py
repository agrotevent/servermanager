"""E-mail notifications."""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage

from sqlalchemy.orm import Session

from . import settings

log = logging.getLogger(__name__)


def mail_configured(db: Session) -> bool:
    return bool(settings.get(db, "mail.enabled") and settings.get(db, "mail.host") and settings.get(db, "mail.sender"))


def recipients(value: str) -> list[str]:
    return [r.strip() for r in (value or "").replace(";", ",").split(",") if "@" in r]


def send_mail(db: Session, to: list[str], subject: str, body: str) -> None:
    if not to:
        return
    host = settings.get(db, "mail.host")
    port = int(settings.get(db, "mail.port") or 587)
    security = settings.get(db, "mail.security")
    user = settings.get(db, "mail.user")
    password = settings.get(db, "mail.password")
    msg = EmailMessage()
    msg["Subject"] = f"[{settings.get(db, 'general.site_name')}] {subject}"
    msg["From"] = settings.get(db, "mail.sender")
    msg["To"] = ", ".join(to)
    msg.set_content(body)
    ctx = ssl.create_default_context()
    if security == "ssl":
        server: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=30, context=ctx)
    else:
        server = smtplib.SMTP(host, port, timeout=30)
    try:
        server.ehlo()
        if security == "starttls":
            server.starttls(context=ctx)
            server.ehlo()
        if user:
            server.login(user, password)
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except smtplib.SMTPException:
            pass


def notify(db: Session, to: list[str], subject: str, body: str) -> bool:
    """Send a mail if mail is configured; never raises."""
    if not to or not mail_configured(db):
        return False
    try:
        send_mail(db, to, subject, body)
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("sending mail failed: %s", exc)
        return False
