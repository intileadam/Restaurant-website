"""SMTP utilities.
- Builds and sends EmailMessage with HTML body.
- Supports retries and small delays between sends.
"""
from __future__ import annotations
import os, time, smtplib
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Iterable


RETIES = 2


class SmtpClient:
    def __init__(self):
        self.host = os.getenv("SMTP_HOST")
        self.port = int(os.getenv("SMTP_PORT", "587"))
        self.user = os.getenv("EMAIL_USER")
        self.password = os.getenv("EMAIL_PASSWORD")
        self.from_name = os.getenv("FROM_NAME", "Casa del Pollo")
        self.from_email = os.getenv("FROM_EMAIL")


    def _connect(self):
        local_hostname = self.from_email.split("@")[-1] if self.from_email else None
        server = smtplib.SMTP(self.host, self.port, timeout=30, local_hostname=local_hostname)
        server.ehlo()
        server.starttls()
        server.ehlo()  # Refresh capabilities after STARTTLS
        server.login(self.user, self.password)
        return server


    def build_message(self, to_email: str, subject: str, html_body: str, text_alt: str | None = None) -> EmailMessage:
        msg = EmailMessage()
        msg["From"] = f"{self.from_name} <{self.from_email}>"
        msg["To"] = to_email
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain=self.from_email.split("@")[-1]) if self.from_email else make_msgid()
        if text_alt:
            msg.set_content(text_alt)
            msg.add_alternative(html_body, subtype="html")
        else:
            # HTML-only works, but multipart/alternative improves deliverability; we can auto-generate later.
            msg.add_alternative(html_body, subtype="html")
        return msg


    def send(self, msg: EmailMessage, delay_ms: int = 0):
        last_err = None
        for attempt in range(RETIES + 1):
            try:
                with self._connect() as server:
                    refused = server.send_message(msg)
                    if refused:
                        raise smtplib.SMTPRecipientsRefused(refused)
                if delay_ms:
                    time.sleep(delay_ms / 1000.0)
                return True
            except Exception as e:
                last_err = e
                time.sleep(0.5 * (attempt + 1))
        if last_err:
            raise last_err
        return False
