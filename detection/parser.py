"""
detection/parser.py - Email Text & Header Parsing Utilities
------------------------------------------------------------
Student explanation:
This module splits raw text emails into structural components: From, Reply-To,
Subject, and Body. It also cleans and normalizes domains and unicode characters
so attackers cannot bypass text filters using homoglyphs (lookalike characters).
"""

import re
import unicodedata


def normalize_unicode(text):
    """
    Converts Unicode lookalike characters back into standard ASCII equivalents.
    For example, attackers use bold/italic mathematical unicode like '𝙑𝙚𝙧𝙞𝙛𝙮'
    or Cyrillic lookalikes to fool simple keyword filters. NFKD decomposes
    these symbols back to plain Latin 'Verify'.
    """
    if not text:
        return ""
    normalized = unicodedata.normalize("NFKD", text)
    return "".join(c for c in normalized if ord(c) < 128)


def get_base_domain(domain):
    """
    Extracts the root/base domain from a hostname.
    Example: 'mail.sub.company.com' -> 'company.com'
    Used when comparing From and Reply-To addresses to prevent false positives
    caused by subdomains.
    """
    if not domain:
        return ""
    parts = domain.strip().lower().split(".")
    if len(parts) >= 2:
        return parts[-2] + "." + parts[-1]
    return domain.strip().lower()


def extract_domain(email_address):
    """
    Extracts and normalizes the domain part of an email address.
    Handles 'Security Team <alert@corp.com>' as well as raw 'alert@corp.com'.
    """
    if not email_address:
        return ""
    if "<" in email_address and ">" in email_address:
        email_address = email_address.split("<")[1].split(">")[0]
    if "@" not in email_address:
        return ""
    return email_address.split("@")[1].strip().lower()


def extract_email_parts(raw_email):
    """
    Parses a raw email string (RFC 822 format or pasted text) into
    discrete headers and body sections.
    """
    if not raw_email:
        return {
            "from_address": "",
            "reply_to": "",
            "subject": "",
            "body": ""
        }

    parts = raw_email.strip().split("\n\n", 1)
    headers = parts[0] if len(parts) > 0 else ""
    body = parts[1] if len(parts) > 1 else ""

    # If no double newline exists, the entire text may be the body
    if not re.search(r"^(From|Subject|To|Reply-To):", headers, re.IGNORECASE | re.MULTILINE):
        body = raw_email
        headers = ""

    from_match = re.search(r"^From:[\s\t]*(.+)$", headers, re.IGNORECASE | re.MULTILINE)
    from_address = from_match.group(1).strip() if from_match else ""
    if "<" in from_address and ">" in from_address:
        from_address = from_address.split("<")[1].split(">")[0].strip()

    reply_to_match = re.search(r"^Reply-To:[\s\t]*(.+)$", headers, re.IGNORECASE | re.MULTILINE)
    reply_to = reply_to_match.group(1).strip() if reply_to_match else ""
    if "<" in reply_to and ">" in reply_to:
        reply_to = reply_to.split("<")[1].split(">")[0].strip()

    subject_match = re.search(r"^Subject:[\s\t]*(.+)$", headers, re.IGNORECASE | re.MULTILINE)
    subject = subject_match.group(1).strip() if subject_match else ""

    return {
        "from_address": from_address,
        "reply_to": reply_to,
        "subject": subject,
        "body": body
    }
