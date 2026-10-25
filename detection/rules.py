"""
detection/rules.py - Rule-Based Heuristic Detection Checks
----------------------------------------------------------
Student explanation:
This module contains 12 independent, fully self-contained heuristic rules.
Detection is completely rule-based and operates offline without requiring any machine
learning models or external internet connections.

Checks evaluate indicators like typosquatting, fake urgency, sensitive credential prompts,
reply-to spoofing, and the local blocklist (combining KNOWN_BAD_DOMAINS from config.py
and the database blocked_sender table).

External threat intelligence (VirusTotal) is strictly optional (ENABLE_VIRUSTOTAL=False
by default) and is never invoked unless explicitly enabled with a valid API key.
"""

import re
import base64
import requests
from detection.parser import normalize_unicode, get_base_domain, extract_domain

# ─── REPUTATION & THREAT LISTS ─────────────────────────────────

TRUSTED_DOMAINS = [
    "corporate.local", "gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
    "icloud.com", "protonmail.com", "live.com", "github.com",
    "apple.com", "paypal.com", "amazon.com", "microsoft.com",
    "google.com", "facebook.com", "instagram.com", "twitter.com",
    "linkedin.com", "netflix.com", "spotify.com", "dropbox.com"
]

URGENCY_KEYWORDS = [
    "act now", "immediately", "urgent", "24 hours", "48 hours",
    "account will be closed", "suspended", "locked", "compromised",
    "expired", "verify now", "confirm now", "failure to act",
    "legal action", "unauthorized access"
]

SENSITIVE_KEYWORDS = [
    "password", "credit card", "social security", "ssn",
    "bank account", "date of birth", "mother's maiden name",
    "pin number", "cvv", "billing information", "payment details"
]

SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".work", ".buzz"]

URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"]

TOO_GOOD_KEYWORDS = [
    "you have won", "you are selected", "free gift",
    "claim your prize", "you have been chosen", "lucky winner",
    "inheritance", "lottery", "million dollars",
    "investment opportunity", "double your money"
]

MANIPULATION_KEYWORDS = [
    "don't tell anyone", "keep this confidential",
    "this is between us", "private offer",
    "secret", "only you", "specially selected"
]

KNOWN_BRANDS = [
    "paypal", "apple", "amazon", "microsoft", "netflix",
    "google", "facebook", "instagram", "bank", "dhl",
    "fedex", "ups", "twitter", "linkedin", "spotify"
]

ATTACHMENT_KEYWORDS = [
    "open attached", "see attachment", "download file",
    "invoice attached", "document attached"
]

MONEY_KEYWORDS = [
    "stimulus", "unclaimed funds", "pending approval",
    "financial benefit", "claim your funds", "verify eligibility",
    "you are eligible", "pending allocation", "benefit amount",
    "approved for $", "claim unclaimed"
]


# ─── LOCAL BLOCKLIST & HEURISTIC RULES ─────────────────────────

def check_blocklist(sender_domain, body, known_bad_domains=None, custom_blocked=None):
    """
    Check: Local Blocklist & Malicious Domain Detection
    Inspects both the sender domain and all links embedded in the body against:
      1. KNOWN_BAD_DOMAINS list from config.py
      2. The database 'blocked_sender' table
      3. Any custom blocked domains supplied by the caller
    Runs 100% locally and self-contained with no external network calls.
    """
    findings = []
    score = 0

    blocked_targets = set()
    if known_bad_domains:
        for d in known_bad_domains:
            if d:
                blocked_targets.add(d.strip().lower())
    if custom_blocked:
        for c in custom_blocked:
            if c:
                blocked_targets.add(c.strip().lower())

    # Safely query the blocked_sender table if running within application context
    try:
        from models import BlockedSender
        db_records = BlockedSender.query.all()
        for rec in db_records:
            if rec.sender_value:
                blocked_targets.add(rec.sender_value.strip().lower())
    except Exception:
        # DB query fails gracefully if offline or outside app context
        pass

    if not blocked_targets:
        return {
            "name": "Local Blocklist",
            "score": 0,
            "message": "No blocklist targets configured"
        }

    norm_sender = sender_domain.strip().lower() if sender_domain else ""
    sender_base = get_base_domain(norm_sender)

    # 1. Evaluate sender domain against blocklist
    for bad in blocked_targets:
        if norm_sender and (norm_sender == bad or sender_base == bad or bad in norm_sender):
            score += 60
            findings.append(f"sender domain '{norm_sender}' matches blocklist entry '{bad}'")
            break

    # 2. Extract and inspect all link hostnames in email body
    link_hosts = re.findall(r'https?://([^\s/:"\'>]+)', body or "")
    matched_links = set()
    for host in link_hosts:
        h_clean = host.strip().lower()
        h_base = get_base_domain(h_clean)
        for bad in blocked_targets:
            if h_clean == bad or h_base == bad or bad in h_clean:
                matched_links.add(f"embedded link '{h_clean}' matches '{bad}'")
                break

    if matched_links:
        score += 50
        findings.extend(list(matched_links)[:3])

    score = min(score, 80)

    if findings:
        return {
            "name": "Local Blocklist",
            "score": score,
            "message": f"Blocklist triggers: {'; '.join(findings)}"
        }

    return {
        "name": "Local Blocklist",
        "score": 0,
        "message": "No sender domain or embedded link domains matched the local blocklist"
    }


def check_trusted_domain(domain, trusted_list=None):
    """
    Check 1: Trusted Domain Whitelist
    Determines if the sender domain is recognized in the corporate trusted list.
    Uses TRUSTED_DOMAINS from config.py (including 'corporate.local') so internal
    staff emails are never penalized.
    """
    if not domain:
        return {"name": "Trusted Domain", "score": 0, "message": "No sender domain found"}

    if trusted_list is None:
        try:
            from config import Config
            trusted_list = getattr(Config, "TRUSTED_DOMAINS", TRUSTED_DOMAINS)
        except Exception:
            trusted_list = TRUSTED_DOMAINS

    clean_d = domain.strip().lower()
    clean_base = get_base_domain(clean_d)

    if clean_d in trusted_list or clean_base in trusted_list:
        return {
            "name": "Trusted Domain",
            "score": 0,
            "message": f"Sender domain '{clean_d}' is recognized as trusted"
        }
    return {
        "name": "Trusted Domain",
        "score": 20,
        "message": f"Sender domain '{clean_d}' is not on the recognized trusted domain whitelist"
    }


def check_typosquatting(domain):
    """
    Check 2: Typosquatting / Lookalike Domain Detection
    Detects common character substitutions (e.g. 0 for o, 1 for l, rn for m)
    aimed at masquerading as legitimate high-profile domains.
    """
    if not domain:
        return {"name": "Typosquatting", "score": 0, "message": "No domain to check for typosquatting"}

    normalized = domain
    normalized = normalized.replace("0", "o")
    normalized = normalized.replace("1", "l")
    normalized = normalized.replace("3", "e")
    normalized = normalized.replace("rn", "m")
    normalized = normalized.replace("vv", "w")

    if domain not in TRUSTED_DOMAINS and normalized in TRUSTED_DOMAINS:
        return {
            "name": "Typosquatting",
            "score": 40,
            "message": f"Suspicious domain '{domain}' looks like '{normalized}' — possible typosquatting detected"
        }
    return {
        "name": "Typosquatting",
        "score": 0,
        "message": f"No typosquatting detected in '{domain}'"
    }


def check_reply_to_mismatch(from_address, reply_to):
    """
    Check 3: Reply-To Header Spoofing / Mismatch
    Compares base domains between the sender (From) and recipient reply target (Reply-To).
    Mismatches indicate return-path hijacking.
    """
    if not reply_to:
        return {"name": "Reply-To Mismatch", "score": 0, "message": "No Reply-To header found"}

    from_domain = extract_domain(from_address)
    reply_to_domain = extract_domain(reply_to)

    from_base = get_base_domain(from_domain)
    reply_to_base = get_base_domain(reply_to_domain)

    if from_base and reply_to_base and from_base == reply_to_base:
        return {
            "name": "Reply-To Mismatch",
            "score": 0,
            "message": f"Reply-To base domain matches From domain '{from_base}'"
        }
    return {
        "name": "Reply-To Mismatch",
        "score": 35,
        "message": f"Reply-To domain '{reply_to_domain}' does not match From domain '{from_domain}' — possible hijacking"
    }


def check_urgency(subject, body):
    """
    Check 4: Urgency & Threat Language Analysis
    Flags high-pressure social engineering psychological triggers.
    """
    text = normalize_unicode((subject + " " + body).lower())
    score = 0
    found_keywords = []

    for keyword in URGENCY_KEYWORDS:
        if keyword in text:
            score += 15
            found_keywords.append(keyword)

    score = min(score, 45)
    if found_keywords:
        return {
            "name": "Urgency Language",
            "score": score,
            "message": f"Urgency keywords detected: {', '.join(found_keywords)}"
        }
    return {"name": "Urgency Language", "score": 0, "message": "No artificial urgency keywords detected"}


def check_sensitivity(body):
    """
    Check 5: Sensitive Information Request
    Flags attempts to harvest credentials, banking numbers, or identity tokens.
    """
    if not body:
        return {"name": "Credential Harvesting", "score": 0, "message": "No body content to evaluate"}

    text = normalize_unicode(body.lower())
    score = 0
    sensitive_found = []

    for sensitive in SENSITIVE_KEYWORDS:
        if sensitive in text:
            score += 30
            sensitive_found.append(sensitive)

    score = min(score, 60)
    if sensitive_found:
        return {
            "name": "Credential Harvesting",
            "score": score,
            "message": f"Sensitive data requests found: {', '.join(sensitive_found)}"
        }
    return {"name": "Credential Harvesting", "score": 0, "message": "No sensitive credential requests detected"}


def check_suspicious_links(body):
    """
    Check 6: Suspicious Links & Attachment Indicators
    Inspects URL patterns: raw IP addresses, URL shorteners, risky TLDs,
    excessive hyphens, and deceptive brand prefixes.
    """
    if not body:
        return {"name": "Link Inspection", "score": 0, "message": "No email body to inspect"}

    text = body.lower()
    score = 0
    findings = []

    ip_pattern = re.findall(r'http[s]?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', body)
    if ip_pattern:
        score += 25
        findings.append(f"raw IP address in URL: {ip_pattern[0]}")

    for shortener in URL_SHORTENERS:
        if shortener in text:
            score += 25
            findings.append(f"URL shortener: {shortener}")

    for tld in SUSPICIOUS_TLDS:
        if tld in text:
            score += 25
            findings.append(f"high-risk TLD: {tld}")

    hyphen_pattern = re.findall(r'http[s]?://[\w]+-[\w]+-[\w]+\.\w+', body)
    if hyphen_pattern:
        score += 25
        findings.append(f"multi-hyphen domain structure: {hyphen_pattern[0]}")

    for keyword in ATTACHMENT_KEYWORDS:
        if keyword in text:
            score += 25
            findings.append(f"suspicious attachment prompt: '{keyword}'")

    lookalike_patterns = [
        "appleid-", "apple-", "paypal-", "amazon-",
        "microsoft-", "google-", "facebook-", "netflix-",
        "secure-login", "verify-account", "account-verify"
    ]
    for pattern in lookalike_patterns:
        if pattern in text:
            score += 25
            findings.append(f"lookalike prefix pattern: '{pattern}'")

    score = min(score, 50)
    if findings:
        return {
            "name": "Link Inspection",
            "score": score,
            "message": f"Suspicious link patterns found: {', '.join(findings)}"
        }
    return {"name": "Link Inspection", "score": 0, "message": "No suspicious links or risky attachments detected"}


def check_too_good(body):
    """
    Check 7: Too Good To Be True Scams
    Flags lottery winnings, prize selection, and inheritance fraud.
    """
    if not body:
        return {"name": "Lure Check", "score": 0, "message": "No body content to evaluate"}

    text = normalize_unicode(body.lower())
    found = [kw for kw in TOO_GOOD_KEYWORDS if kw in text]
    score = min(len(found) * 25, 50)

    if found:
        return {
            "name": "Lure Check",
            "score": score,
            "message": f"Too-good-to-be-true lure keywords: {', '.join(found)}"
        }
    return {"name": "Lure Check", "score": 0, "message": "No fraudulent reward lures detected"}


def check_manipulation(body):
    """
    Check 8: Psychological Secrecy & Isolation
    Flags coercion urging victims not to inform colleagues or authorities.
    """
    if not body:
        return {"name": "Psychological Manipulation", "score": 0, "message": "No body content"}

    text = normalize_unicode(body.lower())
    found = [kw for kw in MANIPULATION_KEYWORDS if kw in text]
    score = min(len(found) * 20, 40)

    if found:
        return {
            "name": "Psychological Manipulation",
            "score": score,
            "message": f"Secrecy/isolation manipulation: {', '.join(found)}"
        }
    return {"name": "Psychological Manipulation", "score": 0, "message": "No isolation tactics detected"}


def check_brand_impersonation(subject, body, sender_domain):
    """
    Check 9: Brand Impersonation Detection
    Compares famous brand names in the text with the actual sender domain.
    """
    text = normalize_unicode((subject + " " + body).lower())
    found_brands = []

    official_domains = {
        "paypal": "paypal.com", "apple": "apple.com",
        "amazon": "amazon.com", "microsoft": "microsoft.com",
        "netflix": "netflix.com", "google": "google.com",
        "facebook": "facebook.com", "instagram": "instagram.com",
        "dhl": "dhl.com", "fedex": "fedex.com", "ups": "ups.com",
        "twitter": "twitter.com", "linkedin": "linkedin.com",
        "spotify": "spotify.com", "bank": ""
    }

    for brand in KNOWN_BRANDS:
        if brand in text:
            official = official_domains.get(brand, "")
            if official and sender_domain != official:
                found_brands.append(brand)
            elif not official and brand not in sender_domain:
                found_brands.append(brand)

    if found_brands:
        return {
            "name": "Brand Impersonation",
            "score": 40,
            "message": f"Brand impersonation detected: mentions '{', '.join(found_brands)}' but sent from '{sender_domain}'"
        }
    return {"name": "Brand Impersonation", "score": 0, "message": "No brand impersonation detected"}


def check_formatting(subject, body):
    """
    Check 10: Formatting & Syntax Anomalies
    Flags excessive punctuation and ALL CAPS hysteria.
    """
    text = subject + " " + body
    score = 0
    findings = []

    excl = text.count("!")
    if excl >= 3:
        score += 10
        findings.append(f"{excl} exclamation marks")

    qmarks = text.count("?")
    if qmarks >= 3:
        score += 10
        findings.append(f"{qmarks} question marks")

    caps_words = [w for w in text.split() if w.isupper() and len(w) > 2]
    if len(caps_words) >= 3:
        score += 10
        findings.append(f"ALL CAPS words: {', '.join(caps_words[:4])}")

    score = min(score, 30)
    if findings:
        return {
            "name": "Formatting Anomalies",
            "score": score,
            "message": f"Erratic formatting signals: {', '.join(findings)}"
        }
    return {"name": "Formatting Anomalies", "score": 0, "message": "Normal formatting"}


def check_money_scam(subject, body):
    """
    Check 11: Financial & Advance-Fee Fraud Indicators
    Detects stimulus claims, unclaimed funds, and suspicious cash promises.
    """
    text = normalize_unicode((subject + " " + body).lower())
    score = 0
    findings = []

    for keyword in MONEY_KEYWORDS:
        if keyword in text:
            score += 25
            findings.append(f"keyword '{keyword}'")

    dollar_matches = re.findall(r'\$[\d,]+', subject + " " + body)
    if dollar_matches:
        score += 25
        findings.append(f"prominent dollar figure: {dollar_matches[0]}")

    score = min(score, 50)
    if findings:
        return {
            "name": "Financial Fraud",
            "score": score,
            "message": f"Financial fraud indicators: {', '.join(findings)}"
        }
    return {"name": "Financial Fraud", "score": 0, "message": "No financial fraud signals detected"}


# ─── OPTIONAL EXTERNAL THREAT INTELLIGENCE (VIRUSTOTAL) ────────

def scan_domain_virustotal(domain, api_key=None, enabled=False):
    """
    Queries VirusTotal API v3 for sender domain reputation.
    Strictly optional. Never called when enabled is False or api_key is missing.
    """
    if not enabled or not domain or not api_key:
        return None

    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers, timeout=5)

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0:
                return {
                    "name": "VirusTotal Domain Intel",
                    "score": 50,
                    "message": f"Domain '{domain}' flagged MALICIOUS by {malicious} security engines"
                }
            elif suspicious > 0:
                return {
                    "name": "VirusTotal Domain Intel",
                    "score": 25,
                    "message": f"Domain '{domain}' flagged SUSPICIOUS by {suspicious} security engines"
                }
            return {
                "name": "VirusTotal Domain Intel",
                "score": 0,
                "message": f"VirusTotal found no threats for domain '{domain}'"
            }
        return {"name": "VirusTotal Domain Intel", "score": 0, "message": "VirusTotal domain lookup returned no result"}
    except Exception as e:
        return {"name": "VirusTotal Domain Intel", "score": 0, "message": f"VirusTotal lookup error: {str(e)}"}


def scan_urls_virustotal(body, api_key=None, enabled=False):
    """
    Queries VirusTotal API v3 for URLs embedded in the email body.
    Strictly optional. Never called when enabled is False or api_key is missing.
    """
    if not enabled or not body or not api_key:
        return None

    urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', body)
    if not urls:
        return {"name": "VirusTotal URL Intel", "score": 0, "message": "No external URLs found in email body"}

    malicious_urls = []
    suspicious_urls = []

    try:
        for target_url in urls[:3]:  # Check first 3 links
            url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {"x-apikey": api_key}
            response = requests.get(endpoint, headers=headers, timeout=5)

            if response.status_code == 200:
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                if stats.get("malicious", 0) > 0:
                    malicious_urls.append(target_url)
                elif stats.get("suspicious", 0) > 0:
                    suspicious_urls.append(target_url)

        if malicious_urls:
            return {
                "name": "VirusTotal URL Intel",
                "score": 50,
                "message": f"Flagged malicious URLs: {', '.join(malicious_urls)}"
            }
        elif suspicious_urls:
            return {
                "name": "VirusTotal URL Intel",
                "score": 25,
                "message": f"Flagged suspicious URLs: {', '.join(suspicious_urls)}"
            }
        return {"name": "VirusTotal URL Intel", "score": 0, "message": "No malicious URLs identified by VirusTotal"}
    except Exception as e:
        return {"name": "VirusTotal URL Intel", "score": 0, "message": f"VirusTotal URL error: {str(e)}"}
