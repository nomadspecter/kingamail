"""
detection/scoring.py - Threat Scoring Matrix & Verdict Decision Pipeline
========================================================================
Student Explanation:
Aggregates outcomes from all 12 heuristic detection checks into an explainable,
points-based risk score (0 to 100+), determines confidence, and maps the total
score to an operational security verdict:

Custom Verdict Thresholds:
  - 0 to 24 points:   'Safe'       -> Delivered directly to employee mailbox.
  - 25 to 54 points:  'Suspicious' -> Delivered with an amber security warning banner.
  - 55+ points:       'Quarantine' -> Automatically isolated away from the mailbox.

DETECTION IS 100% SELF-CONTAINED AND DETERMINISTIC:
Zero machine learning, zero external API dependencies, and fully explainable point scoring.
"""

from detection.parser import (
    extract_email_parts,
    extract_domain
)
from detection.rules import (
    check_blocklist,
    check_trusted_domain,
    check_display_name_spoof,
    check_kenya_telecom_mpesa,
    check_kenya_government_compliance,
    check_kenya_financial_sacco,
    check_tender_invoice_fraud,
    check_free_training_lure,
    check_typosquatting_lookalikes,
    check_urgency_coercion,
    check_credential_harvesting,
    check_suspicious_hyperlinks
)

# Custom Scoring Thresholds
THRESHOLD_SAFE_MAX = 24
THRESHOLD_SUSPICIOUS_MAX = 54
# 55+ points = Quarantine


def analyze_email(raw_email: str, enable_virustotal: bool = False, vt_api_key: str = None, known_bad_domains=None, custom_blocked=None) -> dict:
    """
    Evaluates raw email text or discrete fields against the 12 Kenyan-tailored
    heuristic rules. Completely offline and deterministic.

    Returns:
      {
        "verdict": "Safe" | "Suspicious" | "Quarantine",
        "total_score": int,
        "confidence": "Low" | "Medium" | "High",
        "triggered_count": int,
        "checks": list of check dicts,
        "parsed": dict of parsed email components
      }
    """
    parsed = extract_email_parts(raw_email)
    from_name = parsed["from_name"]
    from_address = parsed["from_address"]
    reply_to = parsed["reply_to"]
    subject = parsed["subject"]
    body = parsed["body"]

    sender_domain = extract_domain(from_address)

    # Resolve configuration fallbacks cleanly
    if known_bad_domains is None:
        try:
            from flask import current_app
            if current_app:
                known_bad_domains = current_app.config.get("KNOWN_BAD_DOMAINS", [])
        except Exception:
            try:
                from config import Config
                known_bad_domains = getattr(Config, "KNOWN_BAD_DOMAINS", [])
            except Exception:
                known_bad_domains = []

    # Run all 12 custom heuristic checks
    checks = [
        check_blocklist(sender_domain, body, known_bad_domains=known_bad_domains, custom_blocked=custom_blocked),
        check_trusted_domain(sender_domain),
        check_display_name_spoof(from_name, sender_domain),
        check_kenya_telecom_mpesa(subject, body),
        check_kenya_government_compliance(subject, body, sender_domain),
        check_kenya_financial_sacco(subject, body, sender_domain),
        check_tender_invoice_fraud(subject, body),
        check_free_training_lure(subject, body),
        check_typosquatting_lookalikes(sender_domain, body),
        check_urgency_coercion(subject, body),
        check_credential_harvesting(body),
        check_suspicious_hyperlinks(body)
    ]

    # Calculate cumulative risk score
    total_score = sum(c["score"] for c in checks)
    triggered_count = sum(1 for c in checks if c["triggered"])

    # Map score to custom security verdict
    if total_score <= THRESHOLD_SAFE_MAX:
        verdict = "Safe"
    elif total_score <= THRESHOLD_SUSPICIOUS_MAX:
        verdict = "Suspicious"
    else:
        verdict = "Quarantine"

    # Compute confidence rating based on corroborating signals
    if triggered_count >= 3 or total_score >= 60:
        confidence = "High"
    elif triggered_count >= 1 or total_score >= 25:
        confidence = "Medium"
    else:
        confidence = "Low"

    return {
        "verdict": verdict,
        "total_score": total_score,
        "confidence": confidence,
        "triggered_count": triggered_count,
        "checks": checks,
        "parsed": parsed
    }
