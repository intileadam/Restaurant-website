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
<hr>
<p style="font-size:12px; color:#666;">You are receiving this because you dined with us or subscribed in-store.
If you’d like to stop receiving emails, <a href="{{ unsubscribe_url }}">unsubscribe here</a>.
</p>
""".strip()




def load_campaign_html(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()




def ensure_unsubscribe(html: str) -> str:
    """If {{ unsubscribe_url }} is not present, append default footer.
    We do this during SEND, not for preview, so the author’s HTML remains as-authored.
    """
    if "{{ unsubscribe_url }}" in html:
        return html
    # Append before closing </body> if present, else at end.
    if "</body>" in html.lower():
        return re.sub(r"</body>\s*$", DEFAULT_FOOTER + "\n</body>", html, flags=re.IGNORECASE)
    return html + "\n" + DEFAULT_FOOTER




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
