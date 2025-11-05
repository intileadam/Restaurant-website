"""Email HTML linter (heuristic checks tuned for common client constraints).
Returns a dict with {errors: [...], warnings: [...], notes: [...]}.
"""

from __future__ import annotations
from bs4 import BeautifulSoup
import re

# Tags generally unsafe/unsupported in email
BLOCK_TAGS = {"script", "form", "video", "audio", "iframe", "canvas", "object"}

# Commonly unsupported CSS patterns in email clients
UNSUPPORTED_CSS = [
    r"position\s*:\s*fixed",
    r"@import",
    r":hover\s*",
]

def lint_html(html: str) -> dict:
    """Run heuristic lint checks against an HTML email string."""
    report = {"errors": [], "warnings": [], "notes": []}

    if not isinstance(html, str):
        report["errors"].append("Input must be a string of HTML.")
        return report

    try:
        soup = BeautifulSoup(html or "", "html.parser")
    except Exception as e:
        report["errors"].append(f"Failed to parse HTML: {e!r}")
        return report

    # 1) Disallowed/unsupported block-level tags
    for t in BLOCK_TAGS:
        found = soup.find_all(t)
        if found:
            report["errors"].append(
                f"Found <{t}> ({len(found)}). Remove for email compatibility."
            )

    # 2) CSS checks: <style> blocks and inline styles
    #    Look for patterns that are known to be flaky in email clients.
    style_blocks = soup.find_all("style")
    for sb in style_blocks:
        css = sb.get_text() or ""
        for pat in UNSUPPORTED_CSS:
            if re.search(pat, css, flags=re.I):
                report["warnings"].append(
                    f"Unsupported CSS in <style>: matches /{pat}/"
                )

    for el in soup.find_all(attrs={"style": True}):
        css = el.get("style") or ""
        for pat in UNSUPPORTED_CSS:
            if re.search(pat, css, flags=re.I):
                name = el.name or "element"
                report["warnings"].append(
                    f"Unsupported inline CSS on <{name}>: matches /{pat}/"
                )

    # 3) Images should have alt text
    for img in soup.find_all("img"):
        alt = img.get("alt")
        if alt is None or alt.strip() == "":
            report["warnings"].append("Image missing alt text.")

    # 4) External HTTP resources (non-HTTPS)
    for tag in soup.find_all(["img", "link", "script"]):
        src = tag.get("src") or tag.get("href")
        if src and isinstance(src, str) and src.startswith("http://"):
            report["warnings"].append(f"Insecure resource: {src} — prefer HTTPS.")

    # 5) Size heuristics
    try:
        if len((html or "").encode("utf-8")) > 100_000:
            report["warnings"].append("HTML size > 100KB; may clip in some clients.")
    except Exception:
        # Extremely defensive—shouldn't really happen
        pass

    # 6) Title/meta presence
    if not soup.find("title"):
        report["notes"].append(
            "No <title> found; subject is separate, but <title> can help some clients."
        )
    if not soup.find("meta", attrs={"charset": True}):
        report["notes"].append("No <meta charset> found; UTF-8 recommended.")

    # 7) Unsubscribe token placeholder (your app auto-appends if missing)
    html_text = str(soup)
    if "{{ unsubscribe_url }}" not in html_text:
        report["notes"].append(
            "No {{ unsubscribe_url }} placeholder; we'll auto-append a footer on send."
        )

    return report
