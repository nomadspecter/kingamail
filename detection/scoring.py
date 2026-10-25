"""
detection/scoring.py - Scoring Engine & Verdict Aggregation
-----------------------------------------------------------
Student explanation:
This module coordinates the phishing detection engine and aggregates the risk score.

DETECTION IS FULLY RULE-BASED AND SELF-CONTAINED:
  - 100% offline-capable: operates strictly on local heuristic rules, keyword patterns,
    the configured KNOWN_BAD_DOMAINS list, and the database blocked_sender table.
  - Zero machine learning models and zero external network dependencies are required.
  - External threat intelligence (VirusTotal) is strictly optional (ENABLE_VIRUSTOTAL=False
    by default). When it is off, the app NEVER calls VirusTotal or any external service
    during an email scan.

Verdict thresholds:
  - 0 to 30 points:  'Safe' (delivered directly to inbox)
  - 31 to 70 points: 'Suspicious' (warning banner displayed)
  - 71+ points:      'Quarantine' (isolated from employee mailbox)
"""

from detection.parser import extract_email_parts, extract_domain
from detection.rules import (
    check_blocklist,
    check_trusted_domain,
    check_typosquatting,
    check_reply_to_mismatch,
    check_urgency,
    check_sensitivity,
    check_suspicious_links,
    check_too_good,
    check_manipulation,
    check_brand_impersonation,
    check_formatting,
    check_money_scam,
    scan_domain_virustotal,
    scan_urls_virustotal
)


def analyze_email(raw_email, enable_virustotal=None, vt_api_key=None, known_bad_domains=None, custom_blocked=None):
    """
    Analyzes an email string (or RFC headers + body) through all local heuristic rules.
    Detection is fully rule-based and self-contained.
    External threat intelligence (VirusTotal) is never called when disabled.

    Returns:
      {
        "verdict": "Safe" | "Suspicious" | "Quarantine",
        "total_score": int,
        "confidence": "Low" | "Medium" | "High",
        "triggered_count": int,
        "checks": [ ... ],
        "parsed": { ... }
      }
    """
    parts = extract_email_parts(raw_email)
    from_address = parts["from_address"]
    reply_to = parts["reply_to"]
    subject = parts["subject"]
    body = parts["body"]

    sender_domain = extract_domain(from_address)

    # Resolve settings from Flask current_app or Config fallback
    if enable_virustotal is None or known_bad_domains is None:
        try:
            from flask import current_app
            if current_app:
                if enable_virustotal is None:
                    enable_virustotal = current_app.config.get("ENABLE_VIRUSTOTAL", False)
                if vt_api_key is None and enable_virustotal:
                    vt_api_key = current_app.config.get("VIRUSTOTAL_API_KEY", "")
                if known_bad_domains is None:
                    known_bad_domains = current_app.config.get("KNOWN_BAD_DOMAINS", [])
        except Exception:
            pass

    if known_bad_domains is None:
        try:
            from config import Config
            known_bad_domains = getattr(Config, "KNOWN_BAD_DOMAINS", [])
            if enable_virustotal is None:
                enable_virustotal = getattr(Config, "ENABLE_VIRUSTOTAL", False)
            if vt_api_key is None and enable_virustotal:
                vt_api_key = getattr(Config, "VIRUSTOTAL_API_KEY", "")
        except Exception:
            known_bad_domains = []

    # Execute all 12 fully self-contained, offline heuristic checks
    results = [
        check_blocklist(sender_domain, body, known_bad_domains=known_bad_domains, custom_blocked=custom_blocked),
        check_trusted_domain(sender_domain),
        check_typosquatting(sender_domain),
        check_reply_to_mismatch(from_address, reply_to),
        check_urgency(subject, body),
        check_sensitivity(body),
        check_suspicious_links(body),
        check_too_good(body),
        check_manipulation(body),
        check_brand_impersonation(subject, body, sender_domain),
        check_formatting(subject, body),
        check_money_scam(subject, body)
    ]

    # External threat intelligence: ONLY queried when explicitly enabled AND an API key is present.
    # When disabled (the default), this block is skipped completely — NO network calls are made.
    if enable_virustotal and vt_api_key:
        vt_domain = scan_domain_virustotal(sender_domain, api_key=vt_api_key, enabled=True)
        if vt_domain:
            results.append(vt_domain)
        vt_urls = scan_urls_virustotal(body, api_key=vt_api_key, enabled=True)
        if vt_urls:
            results.append(vt_urls)

    # Calculate total risk score across all local and active checks
    total_score = sum(r["score"] for r in results)

    # Calculate detection confidence based on number of triggered independent indicators
    triggered_count = sum(1 for r in results if r["score"] > 0)
    if triggered_count >= 5:
        confidence = "High"
    elif triggered_count >= 3:
        confidence = "Medium"
    else:
        confidence = "Low"

    # Assign corporate verdict based on accumulated score
    if total_score <= 30:
        verdict = "Safe"
    elif total_score <= 70:
        verdict = "Suspicious"
    else:
        verdict = "Quarantine"

    return {
        "verdict": verdict,
        "total_score": total_score,
        "confidence": confidence,
        "triggered_count": triggered_count,
        "checks": results,
        "parsed": parts
    }
