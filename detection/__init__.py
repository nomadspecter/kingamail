"""
detection/__init__.py - Phishing Detection Package
--------------------------------------------------
Student explanation:
This package encapsulates all heuristic and threat intelligence algorithms
responsible for parsing, inspecting, scoring, and classifying emails as
Safe, Suspicious, or Quarantined (Scam).
"""

from detection.parser import extract_email_parts, extract_domain, get_base_domain, normalize_unicode
from detection.scoring import analyze_email

__all__ = [
    "extract_email_parts",
    "extract_domain",
    "get_base_domain",
    "normalize_unicode",
    "analyze_email"
]
