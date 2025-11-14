"""Render layer.
- Loads campaign HTML from disk.
- Injects merge fields and unsubscribe URL.
- Subject is provided in UI, not derived from HTML title.
"""
from __future__ import annotations
import os, re
from jinja2 import Environment, BaseLoader


BASE_URL = os.getenv("BASE_URL_PUBLIC", "https://casadelpollo.com")
UNSUB_PATH = os.getenv("UNSUBSCRIBE_PATH", "/unsubscribe")


_jinja = Environment(loader=BaseLoader(), autoescape=False)


DEFAULT_FOOTER = """
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:24px;">
  <tr>
    <td style="border-top:1px solid #e2e2e2; padding:16px 0; text-align:center; font-size:12px; line-height:1.6; color:#666;">
      <a href="{{ unsubscribe_url }}" style="color:#d62828;">Unsubscribe here</a>
    </td>
  </tr>
</table>
""".strip()



def load_campaign_html(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()




def ensure_unsubscribe(html: str) -> str:
    """Ensure an unsubscribe footer with a Jinja placeholder is present.
    Idempotent: if a placeholder already exists, return html unchanged.
    """
    # If either placeholder exists, do nothing.
    if "{{ unsubscribe_url }}" in html or "{{ UNSUBSCRIBE_URL }}" in html:
        return html

    # Try to inject right before the last </body> (case-insensitive).
    lower = html.lower()
    i = lower.rfind("</body>")
    footer_block = "\n" + DEFAULT_FOOTER + "\n"
    if i != -1:
        return html[:i] + footer_block + html[i:]

    # No </body> found: just append at the end.
    suffix = "" if html.endswith("\n") else "\n"
    return html + suffix + DEFAULT_FOOTER + "\n"




def render_for_recipient(html: str, first_name: str | None, last_name: str | None, token: str) -> str:
    unsubscribe_url = f"{BASE_URL}{UNSUB_PATH}?token={token}"
    template = _jinja.from_string(html)
    # Accept both lowercase and uppercase keys by duplicating.
    ctx = {
        "first_name": first_name or "",
        "last_name": last_name or "",
        "unsubscribe_url": unsubscribe_url,
        "FIRSTNAME": first_name or "",
        "LASTNAME": last_name or "",
        "UNSUBSCRIBE_URL": unsubscribe_url,
    }
    return template.render(**ctx)




def render_for_test(html: str) -> str:
    # For tests, use a dummy, clearly-labeled unsubscribe URL
    template = _jinja.from_string(html)
    unsubscribe_url = f"{BASE_URL}{UNSUB_PATH}?token=TEST_NOT_ACTIVE"
    return template.render(first_name="Test", last_name="Recipient", unsubscribe_url=unsubscribe_url,
                           FIRSTNAME="Test", LASTNAME="Recipient", UNSUBSCRIBE_URL=unsubscribe_url)
