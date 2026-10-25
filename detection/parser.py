"""
detection/parser.py - Enterprise Email Structure & Entity Extraction Engine
=============================================================================
Student Explanation:
Deconstructs raw RFC-822 messages and web scanner inputs into normalized 
components: Sender Display Name, RFC Address, Reply-To, Subject, and Body text.

Also provides Kenyan ccTLD domain extraction (handling .co.ke, .go.ke, .ac.ke, .or.ke)
and Unicode homoglyph normalization to disarm character obfuscation tricks.
"""

import re
import email.utils
import unicodedata
from urllib.parse import urlparse


# Common 2-level Kenyan and international country-code second-level domains
KENYAN_AND_CCTLD_SUFFIXES = {
    "co.ke", "go.ke", "or.ke", "ac.ke", "sc.ke", "me.ke",
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "co.za", "gov.za", "ac.za", "org.za",
    "com.ng", "gov.ng", "edu.ng"
}


def normalize_unicode(text: str) -> str:
    """
    Normalizes Unicode obfuscations (e.g., bold/italic math characters, Cyrillic lookalikes)
    into standard Latin ASCII. Also strips zero-width spaces attackers use to split keywords.
    """
    if not text:
        return ""
    # Strip zero-width characters commonly used to defeat keyword matchers
    text = re.sub(r"[\u200B\u200C\u200D\uFEFF\u00AD]", "", text)
    # NFKD decomposition separates base letters from diacritics and stylistic glyphs
    decomposed = unicodedata.normalize("NFKD", text)
    ascii_clean = "".join(c for c in decomposed if ord(c) < 128)
    return ascii_clean


def extract_domain(email_address: str) -> str:
    """
    Extracts the normalized domain part from an email string.
    Works for both 'First Last <user@domain.com>' and raw 'user@domain.com'.
    """
    if not email_address:
        return ""
    # Use standard library parser first
    _, parsed_addr = email.utils.parseaddr(email_address)
    target = parsed_addr if parsed_addr else email_address

    if "<" in target and ">" in target:
        target = target.split("<")[1].split(">")[0]

    if "@" not in target:
        return ""

    return target.split("@")[-1].strip().lower()


def get_base_domain(hostname: str) -> str:
    """
    Extracts the registrable root domain from a hostname.
    Correctly recognizes Kenyan second-level domains like 'safaricom.co.ke'
    and 'kra.go.ke' rather than mistakenly truncating to 'co.ke' or 'go.ke'.
    """
    if not hostname:
        return ""
    cleaned = hostname.strip().lower()
    # Strip protocol or port if present
    if "://" in cleaned:
        cleaned = urlparse(cleaned).netloc or cleaned
    cleaned = cleaned.split(":")[0].strip("/")

    parts = cleaned.split(".")
    if len(parts) <= 2:
        return cleaned

    # Check for known 2-level suffix (e.g. co.ke, go.ke)
    two_level = f"{parts[-2]}.{parts[-1]}"
    if two_level in KENYAN_AND_CCTLD_SUFFIXES:
        return f"{parts[-3]}.{two_level}" if len(parts) >= 3 else cleaned

    return f"{parts[-2]}.{parts[-1]}"


def extract_links(text: str) -> list:
    """
    Extracts all web URLs embedded in HTML or plain-text body content.
    """
    if not text:
        return []
    url_pattern = re.compile(
        r"https?://(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;%=]+)",
        re.IGNORECASE
    )
    raw_urls = url_pattern.findall(text)
    # Deduplicate while preserving discovery order
    seen = set()
    cleaned = []
    for u in raw_urls:
        u_clean = u.rstrip(".,;:)>'\"")
        if u_clean not in seen:
            seen.add(u_clean)
            cleaned.append(u_clean)
    return cleaned


def extract_email_parts(raw_email: str) -> dict:
    """
    Deconstructs a raw email string into discrete header fields,
    sender display name, recipient addresses, and body text.
    """
    if not raw_email:
        return {
            "from_name": "",
            "from_address": "",
            "reply_to": "",
            "reply_to_name": "",
            "subject": "",
            "body": ""
        }

    # Split headers from body at first double newline if RFC formatted
    parts = raw_email.strip().split("\n\n", 1)
    headers = parts[0] if len(parts) > 1 else ""
    body = parts[1] if len(parts) > 1 else raw_email

    # If top section has no RFC header keywords, treat entire text as body
    if not re.search(r"^(From|Subject|To|Reply-To):", headers, re.IGNORECASE | re.MULTILINE):
        body = raw_email
        headers = ""

    from_line_match = re.search(r"^From:[\s\t]*(.+)$", headers, re.IGNORECASE | re.MULTILINE)
    raw_from = from_line_match.group(1).strip() if from_line_match else ""
    from_name, from_address = email.utils.parseaddr(raw_from)
    if not from_address and "@" in raw_from:
        from_address = raw_from.strip("<> ")

    reply_to_match = re.search(r"^Reply-To:[\s\t]*(.+)$", headers, re.IGNORECASE | re.MULTILINE)
    raw_reply_to = reply_to_match.group(1).strip() if reply_to_match else ""
    reply_to_name, reply_to_address = email.utils.parseaddr(raw_reply_to)
    if not reply_to_address and "@" in raw_reply_to:
        reply_to_address = raw_reply_to.strip("<> ")

    subject_match = re.search(r"^Subject:[\s\t]*(.+)$", headers, re.IGNORECASE | re.MULTILINE)
    subject = subject_match.group(1).strip() if subject_match else ""

    return {
        "from_name": from_name.strip("\"' "),
        "from_address": from_address.strip(),
        "reply_to": reply_to_address.strip(),
        "reply_to_name": reply_to_name.strip("\"' "),
        "subject": subject.strip(),
        "body": body.strip()
    }
