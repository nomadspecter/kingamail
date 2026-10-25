"""
detection/rules.py - Enterprise Threat Heuristics & Kenyan Cyber-Fraud Intelligence
===================================================================================
Student Explanation:
Implements 12 deterministic, rule-based heuristic checks tailored specifically for
Kenyan and regional corporate threat landscapes.

All detection is 100% self-contained and operates completely offline without machine
learning models or external internet calls.

Threat Intelligence Focus:
  - Kenyan Mobile Money (M-Pesa, Safaricom prompts, Bonga points, Fuliza, reversal lures)
  - Public Sector Compliance (KRA iTax, eCitizen, HELB loans, SHIF/NHIF statutory levies)
  - Financial Institutions & SACCOs (KCB, Equity Bank, Co-op, Stima SACCO, Harambee SACCO)
  - Public Procurement, County Tenders & BEC Invoice Fraud
  - Free Professional Training & Fellowship Lures (Original Check #1)
  - Mismatched Sender Display-Name Spoofing (Original Check #2)
  - Typosquatted / Homoglyph lookalike domains
  - High-pressure psychological coercion and urgency
  - Sensitive credential & PIN harvesting
  - Suspicious URL anatomy, IP addresses, and high-risk TLDs
"""

import re
from urllib.parse import urlparse
from detection.parser import (
    normalize_unicode,
    get_base_domain,
    extract_domain,
    extract_links
)

# ─── REPUTABLE ORIGINS & CORPORATE WHITELIST ─────────────────────────
DEFAULT_TRUSTED_DOMAINS = [
    "corporate.local",
    "safaricom.co.ke",
    "kra.go.ke",
    "ecitizen.go.ke",
    "helb.co.ke",
    "equitybank.co.ke",
    "kcbgroup.com",
    "co-opbank.co.ke",
    "ncbagroup.com",
    "gmail.com",
    "outlook.com",
    "yahoo.com",
    "microsoft.com",
    "google.com"
]

# ─── KENYAN TELECOM & MOBILE MONEY KEYWORDS ──────────────────────────
MPESA_FRAUD_PATTERNS = [
    r"\bm-?pesa\b",
    r"\bsafaricom\b",
    r"\bfuliza\b",
    r"\bbonga\s*points?\b",
    r"\bsim\s*swap\b",
    r"\bpaybill\b",
    r"\btill\s*number\b",
    r"\breverse\s*(?:transaction|float|payment)\b",
    r"\boverpayment\s*reversal\b",
    r"\bairtime\s*(?:promo|scratch|bonus|voucher)\b",
    r"\bpesa\s*link\b",
    r"\bkes\.?\s*\d+",
    r"\bksh\.?\s*\d+"
]

# ─── KENYAN GOVERNMENT & STATUTORY COMPLIANCE ────────────────────────
KENYA_GOV_PATTERNS = [
    r"\bkra\b",
    r"\bitax\b",
    r"\btax\s*compliance\b",
    r"\bwithholding\s*tax\b",
    r"\bvat\s*penalty\b",
    r"\becitizen\b",
    r"\bhelb\b",
    r"\bhigher\s*education\s*loans?\b",
    r"\bshif\b",
    r"\bnhif\b",
    r"\bnssf\b",
    r"\bcrb\s*(?:listing|clearance)\b",
    r"\bntsa\b",
    r"\bdriving\s*licen[cs]e\b"
]

# ─── KENYAN BANKING & SACCO INSTITUTIONS ─────────────────────────────
KENYA_BANK_SACCO_PATTERNS = [
    r"\bequity\s*bank\b",
    r"\bkcb(?:\s*bank)?\b",
    r"\bco-?operative\s*bank\b",
    r"\bco-?op\s*bank\b",
    r"\bncba\b",
    r"\babsa\s*kenya\b",
    r"\bstanbic\b",
    r"\bfamily\s*bank\b",
    r"\bstima\s*sacco\b",
    r"\bharambee\s*sacco\b",
    r"\bpolice\s*sacco\b",
    r"\bmwalimu\s*(?:national)?\s*sacco\b",
    r"\bafya\s*sacco\b",
    r"\bsacco\s*dividend\b"
]

# ─── PROCUREMENT, TENDER & INVOICE FRAUD ─────────────────────────────
TENDER_INVOICE_PATTERNS = [
    r"\bcounty\s*government\s*tender\b",
    r"\blocal\s*purchase\s*order\b",
    r"\blpo\b",
    r"\btender\s*pre-?qualification\b",
    r"\btender\s*award\b",
    r"\bpublic\s*procurement\b",
    r"\bppra\b",
    r"\bquotation\s*submission\b",
    r"\bnew\s*bank\s*(?:details|account)\b",
    r"\bamended\s*invoice\b",
    r"\bpayment\s*rerouting\b"
]

# ─── FREE TRAINING & FELLOWSHIP LURES ────────────────────────────────
FREE_TRAINING_PATTERNS = [
    r"\bfully\s*funded\s*(?:training|fellowship|workshop|seminar|scholarship)\b",
    r"\bfree\s*cpd\s*(?:points|credits|training)\b",
    r"\bprofessional\s*development\s*fellowship\b",
    r"\bnairobi\s*(?:leadership|executive)\s*fellowship\b",
    r"\bper\s*diem\s*allowance\b",
    r"\bconfer(?:ence)?\s*travel\s*grant\b",
    r"\bunsolicited\s*job\s*offer\b",
    r"\bngo\s*recruitment\s*portal\b"
]

# ─── COERCION & URGENCY INDICATORS ───────────────────────────────────
COERCION_PATTERNS = [
    r"\bimmediate\s*action\s*required\b",
    r"\bwithin\s*(?:1|2|12|24|48)\s*hours\b",
    r"\baccount\s*will\s*be\s*(?:suspended|terminated|deactivated|closed)\b",
    r"\bpolice\s*arrest\b",
    r"\blegal\s*prosecution\b",
    r"\bcrb\s*blacklisting\b",
    r"\bfailure\s*to\s*comply\b",
    r"\bkeep\s*(?:this)?\s*strictly\s*confidential\b",
    r"\bdo\s*not\s*disclose\s*to\s*colleagues\b"
]

# ─── SENSITIVE CREDENTIAL TARGETS ────────────────────────────────────
CREDENTIAL_TARGETS = [
    r"\bpassword\b",
    r"\bm-?pesa\s*pin\b",
    r"\batm\s*pin\b",
    r"\bsecret\s*pin\b",
    r"\botp\b",
    r"\bone[- ]time\s*passcode\b",
    r"\bnational\s*id(?:\s*number)?\b",
    r"\bkra\s*pin\b",
    r"\bcvv\b",
    r"\bcard\s*(?:details|number|expiry)\b"
]

# ─── HIGH-RISK TLDS & SHORTENERS ─────────────────────────────────────
HIGH_RISK_TLDS = {".xyz", ".top", ".buzz", ".work", ".click", ".gq", ".cf", ".tk", ".ml", ".ga"}
POPULAR_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly"}

# ─── LOOKALIKE TARGET BASE NAMES ─────────────────────────────────────
LOOKALIKE_TARGETS = [
    "safaricom", "mpesa", "ecitizen", "kra", "equity", "kcb",
    "coopbank", "ncba", "microsoft", "google", "corporate"
]


# =====================================================================
# RULE CONTRACT DECORATOR & IMPLEMENTATIONS
# =====================================================================

def _rule_contract(func):
    """Ensures consistent dictionary contract containing both details and message keys."""
    def wrapper(*args, **kwargs):
        res = func(*args, **kwargs)
        if isinstance(res, dict):
            if "details" in res and "message" not in res:
                res["message"] = res["details"]
            elif "message" in res and "details" not in res:
                res["details"] = res["message"]
        return res
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper


@_rule_contract
def check_blocklist(sender_domain: str, body: str = "", known_bad_domains=None, custom_blocked=None) -> dict:
    """
    RULE-01: Local Blocklist & Blacklisted Attacker Threat Check
    Verifies sender domain and embedded URL hosts against:
      1. KNOWN_BAD_DOMAINS list from config.py
      2. The database 'blocked_sender' table
    Contributes: +60 pts (Triggers immediate Quarantine)
    """
    findings = []
    score = 0

    if known_bad_domains is None:
        try:
            from config import Config
            known_bad_domains = getattr(Config, "KNOWN_BAD_DOMAINS", [])
        except Exception:
            known_bad_domains = []

    bad_domains = set(d.strip().lower() for d in known_bad_domains if d)
    if custom_blocked:
        bad_domains.update(d.strip().lower() for d in custom_blocked if d)

    # 1. Inspect sender domain
    if sender_domain:
        sender_base = get_base_domain(sender_domain)
        if sender_domain.lower() in bad_domains or sender_base in bad_domains:
            findings.append(f"Sender domain '{sender_domain}' is on the malicious blocklist.")
            score += 60

    # 2. Inspect embedded links in body
    urls = extract_links(body)
    for u in urls:
        host = urlparse(u).hostname or ""
        host_base = get_base_domain(host)
        if host.lower() in bad_domains or host_base in bad_domains:
            findings.append(f"Embedded hyperlink targets blacklisted host '{host}'.")
            score += 60
            break

    triggered = len(findings) > 0
    return {
        "rule_id": "RULE-01-BLOCKLIST",
        "name": "Local Malicious Blocklist",
        "score": min(score, 60),
        "triggered": triggered,
        "category": "Reputation & Blacklist",
        "details": " | ".join(findings) if triggered else "Sender and embedded link domains are not present on local blocklist."
    }


@_rule_contract
def check_trusted_domain(sender_domain: str, trusted_domains=None) -> dict:
    """
    RULE-02: Trusted Domain Whitelist Baseline
    Inspects whether sender originates from the verified internal corporate domain
    (e.g., corporate.local) or recognized reputable service providers.
    Contributes: 0 pts for trusted corporate/internal; +15 pts for external/unknown.
    """
    if trusted_domains is None:
        try:
            from config import Config
            trusted_domains = getattr(Config, "TRUSTED_DOMAINS", DEFAULT_TRUSTED_DOMAINS)
        except Exception:
            trusted_domains = DEFAULT_TRUSTED_DOMAINS

    trusted_set = set(d.strip().lower() for d in trusted_domains if d)
    s_domain = sender_domain.strip().lower() if sender_domain else ""
    s_base = get_base_domain(s_domain)

    is_trusted = (s_domain in trusted_set or s_base in trusted_set)
    score = 0 if is_trusted else 15

    return {
        "rule_id": "RULE-02-TRUSTED-ORIGIN",
        "name": "Trusted Domain Verification",
        "score": score,
        "triggered": not is_trusted,
        "category": "Identity & Origin",
        "details": f"Sender domain '{s_domain}' is verified on the trusted whitelist." if is_trusted else f"Sender domain '{s_domain}' is external or untrusted (+15 pts)."
    }


@_rule_contract
def check_display_name_spoof(from_name: str, sender_domain: str) -> dict:
    """
    RULE-03: Mismatched Display Name & Executive/Authority Impersonation [Original Check #1]
    Detects when the human-readable display name claims to be a recognized authority
    (e.g., 'KRA Support', 'Safaricom M-Pesa', 'Equity Bank Alert', 'Corporate IT Helpdesk')
    while the actual sender email address originates from an unrelated domain.
    Contributes: +45 pts (Significant Phishing Indicator)
    """
    if not from_name or not sender_domain:
        return {
            "rule_id": "RULE-03-DISPLAY-NAME-SPOOF",
            "name": "Mismatched Display Name Spoofing",
            "score": 0,
            "triggered": False,
            "category": "Identity & Origin",
            "details": "Display name matches sender infrastructure or is standard individual name."
        }

    norm_name = normalize_unicode(from_name).lower()
    s_base = get_base_domain(sender_domain.lower())

    # Mapping of high-profile entities to their legitimate base domains
    authority_map = {
        "kra": "kra.go.ke",
        "kenya revenue authority": "kra.go.ke",
        "itax": "kra.go.ke",
        "safaricom": "safaricom.co.ke",
        "m-pesa": "safaricom.co.ke",
        "mpesa": "safaricom.co.ke",
        "ecitizen": "ecitizen.go.ke",
        "helb": "helb.co.ke",
        "equity bank": "equitybank.co.ke",
        "kcb bank": "kcbgroup.com",
        "co-op bank": "co-opbank.co.ke",
        "cooperative bank": "co-opbank.co.ke",
        "stima sacco": "stima-sacco.com",
        "harambee sacco": "harambeesacco.com",
        "it support": "corporate.local",
        "system administrator": "corporate.local",
        "hr directorate": "corporate.local",
        "payroll department": "corporate.local",
        "chief executive": "corporate.local",
        "managing director": "corporate.local"
    }

    triggered = False
    details = "Display name matches sender infrastructure."

    for entity, legitimate_domain in authority_map.items():
        if entity in norm_name:
            if s_base != legitimate_domain and sender_domain.lower() != legitimate_domain:
                triggered = True
                details = f"Display name claims authority '{from_name}' but email originates from untrusted domain '{sender_domain}'."
                break

    return {
        "rule_id": "RULE-03-DISPLAY-NAME-SPOOF",
        "name": "Mismatched Display Name Spoofing",
        "score": 45 if triggered else 0,
        "triggered": triggered,
        "category": "Identity & Origin",
        "details": details
    }


@_rule_contract
def check_kenya_telecom_mpesa(subject: str, body: str) -> dict:
    """
    RULE-04: Kenyan Telecom & M-Pesa Mobile Money Fraud
    Detects M-Pesa reversal lures, Bonga points expiry scams, Fuliza loan settlement demands,
    and Safaricom SIM-swap alerts.
    Contributes: +40 pts
    """
    content = normalize_unicode(f"{subject}\n{body}").lower()
    matched = []

    for pattern in MPESA_FRAUD_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            matched.append(pattern.replace(r"\b", "").replace(r"\s*", " "))

    # Trigger if mobile money term is combined with transaction or action signals
    has_telecom_anchor = any(term in content for term in ["m-pesa", "mpesa", "safaricom", "fuliza", "bonga", "airtime", "sim swap"])
    has_fraud_context = any(term in content for term in ["reverse", "cancel", "expiry", "redeem", "overpayment", "float", "pin", "bonus", "kes", "ksh"])

    triggered = has_telecom_anchor and (has_fraud_context or len(matched) >= 2)
    score = 40 if triggered else 0

    return {
        "rule_id": "RULE-04-KENYA-TELECOM-MPESA",
        "name": "Kenyan Telecom & M-Pesa Fraud",
        "score": score,
        "triggered": triggered,
        "category": "Regional Threat Intelligence",
        "details": f"Flagged mobile money fraud indicators ({len(matched)} patterns matched)." if triggered else "No mobile money fraud signals detected."
    }


@_rule_contract
def check_kenya_government_compliance(subject: str, body: str, sender_domain: str) -> dict:
    """
    RULE-05: Kenyan Public Sector & Revenue Scam Detector
    Detects fake KRA iTax compliance certificates, VAT penalties, eCitizen payment mandates,
    HELB loan default threats, and statutory SHIF/NHIF/NSSF audits.
    Contributes: +45 pts
    """
    content = normalize_unicode(f"{subject}\n{body}").lower()
    s_domain = sender_domain.lower() if sender_domain else ""

    matched = []
    for pattern in KENYA_GOV_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            matched.append(pattern.replace(r"\b", "").replace(r"\s*", " "))

    # If sender is genuinely from a .go.ke government domain, do not penalize
    if s_domain.endswith(".go.ke"):
        return {
            "rule_id": "RULE-05-KENYA-GOV-COMPLIANCE",
            "name": "Government & Statutory Scam Detector",
            "score": 0,
            "triggered": False,
            "category": "Regional Threat Intelligence",
            "details": "Legitimate .go.ke public authority origin verified."
        }

    triggered = len(matched) >= 2 or (len(matched) >= 1 and any(action in content for action in ["penalty", "compliance", "deactivation", "default", "crb", "directive", "audit", "pay"]))
    score = 45 if triggered else 0

    return {
        "rule_id": "RULE-05-KENYA-GOV-COMPLIANCE",
        "name": "Government & Statutory Scam Detector",
        "score": score,
        "triggered": triggered,
        "category": "Regional Threat Intelligence",
        "details": f"Detected unauthorized government/revenue impersonation ({', '.join(matched[:3])})." if triggered else "No statutory tax/government impersonation detected."
    }


@_rule_contract
def check_kenya_financial_sacco(subject: str, body: str, sender_domain: str) -> dict:
    """
    RULE-06: Kenyan Banking & SACCO Impersonation
    Detects unauthorized communications mimicking Kenyan commercial banks
    (KCB, Equity, Co-op, NCBA) and prominent SACCOs (Stima, Harambee, Police).
    Contributes: +40 pts
    """
    content = normalize_unicode(f"{subject}\n{body}").lower()
    s_domain = sender_domain.lower() if sender_domain else ""

    matched_institutions = []
    for pattern in KENYA_BANK_SACCO_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            matched_institutions.append(pattern.replace(r"\b", "").replace(r"\s*", " "))

    # Legitimate bank domain check
    legit_bank_domains = {"equitybank.co.ke", "kcbgroup.com", "co-opbank.co.ke", "ncbagroup.com", "stima-sacco.com"}
    if s_domain in legit_bank_domains:
        return {
            "rule_id": "RULE-06-KENYA-FINANCIAL-SACCO",
            "name": "Kenyan Bank & SACCO Security",
            "score": 0,
            "triggered": False,
            "category": "Regional Threat Intelligence",
            "details": "Verified legitimate commercial banking domain."
        }

    action_context = any(term in content for term in ["blocked", "suspended", "token", "otp", "re-activate", "dividend", "kyc", "verify", "mobile banking"])
    triggered = len(matched_institutions) >= 1 and action_context
    score = 40 if triggered else 0

    return {
        "rule_id": "RULE-06-KENYA-FINANCIAL-SACCO",
        "name": "Kenyan Bank & SACCO Security",
        "score": score,
        "triggered": triggered,
        "category": "Regional Threat Intelligence",
        "details": f"Flagged bank/SACCO brand exploitation from unauthorized domain '{sender_domain}'." if triggered else "No commercial banking impersonation patterns."
    }


@_rule_contract
def check_tender_invoice_fraud(subject: str, body: str) -> dict:
    """
    RULE-07: Public Procurement, County Tender & BEC Invoice Fraud
    Detects forged Local Purchase Orders (LPOs), fraudulent tender pre-qualifications,
    and requests to alter supplier remittance banking details.
    Contributes: +40 pts
    """
    content = normalize_unicode(f"{subject}\n{body}").lower()
    matched = []

    for pattern in TENDER_INVOICE_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            matched.append(pattern.replace(r"\b", "").replace(r"\s*", " "))

    has_tender = any(term in content for term in ["tender", "lpo", "procurement", "quotation", "supply", "invoice"])
    has_financial_demand = any(term in content for term in ["bank account", "remittance", "new account", "pre-qualification", "award", "acceptance"])

    triggered = (len(matched) >= 1 and has_financial_demand) or len(matched) >= 2
    score = 40 if triggered else 0

    return {
        "rule_id": "RULE-07-TENDER-INVOICE-FRAUD",
        "name": "Procurement & BEC Invoice Fraud",
        "score": score,
        "triggered": triggered,
        "category": "Enterprise Threat Defense",
        "details": f"Detected tender pre-qualification or invoice redirection indicators ({', '.join(matched[:3])})." if triggered else "No procurement or invoice diversion patterns."
    }


@_rule_contract
def check_free_training_lure(subject: str, body: str) -> dict:
    """
    RULE-08: Free Professional Training & Fellowship Lure [Original Check #2]
    Detects unsolicited fully-funded corporate training, free CPD certification offers,
    travel allowances, and bogus NGO fellowships designed to lure employees into clicking.
    Contributes: +35 pts
    """
    content = normalize_unicode(f"{subject}\n{body}").lower()
    matched = []

    for pattern in FREE_TRAINING_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            matched.append(pattern.replace(r"\b", "").replace(r"\s*", " "))

    has_lure = any(term in content for term in ["free", "fully funded", "sponsored", "fellowship", "cpd", "scholarship", "allowance"])
    has_call_to_action = any(term in content for term in ["register", "apply now", "limited slots", "portal", "nomination", "enrol", "enroll"])

    triggered = len(matched) >= 1 or (has_lure and has_call_to_action)
    score = 35 if triggered else 0

    return {
        "rule_id": "RULE-08-FREE-TRAINING-LURE",
        "name": "Free Training & Fellowship Lure",
        "score": score,
        "triggered": triggered,
        "category": "Social Engineering",
        "details": "Unsolicited fully-funded corporate fellowship or free CPD lure detected." if triggered else "No deceptive training or fellowship lures identified."
    }


@_rule_contract
def check_typosquatting_lookalikes(sender_domain: str, body: str = "") -> dict:
    """
    RULE-09: Lookalike Domain & Homoglyph Detection
    Replaces leetspeak character substitutions ('0'->'o', '1'->'l', 'rn'->'m', 'vv'->'w')
    to uncover deceptive lookalikes of popular Kenyan and tech brands (safaricom, kra, ecitizen, etc.).
    Contributes: +40 pts
    """
    findings = []
    domains_to_test = set()

    if sender_domain:
        domains_to_test.add(sender_domain.lower())

    for u in extract_links(body):
        host = urlparse(u).hostname
        if host:
            domains_to_test.add(host.lower())

    for domain in domains_to_test:
        base = get_base_domain(domain)
        # Normalize homoglyphs and leetspeak (test both 1->i and 1->l)
        variants = [
            base.replace("0", "o").replace("1", "i").replace("3", "e").replace("5", "s").replace("vv", "w").replace("rn", "m").replace("-", ""),
            base.replace("0", "o").replace("1", "l").replace("3", "e").replace("5", "s").replace("vv", "w").replace("rn", "m").replace("-", "")
        ]

        for target in LOOKALIKE_TARGETS:
            is_match = any(target in v for v in variants)
            if is_match and base != target and not base.startswith(f"{target}."):
                # Exception: legitimate multi-level domain (e.g. safaricom.co.ke)
                if not any(base == f"{target}.{suf}" for suf in ["co.ke", "go.ke", "com", "local"]):
                    findings.append(f"Domain '{base}' appears to typosquat legitimate brand '{target}'.")
                    break

    triggered = len(findings) > 0
    return {
        "rule_id": "RULE-09-TYPOSQUAT-HOMOGLYPH",
        "name": "Lookalike & Typosquatting Defense",
        "score": 40 if triggered else 0,
        "triggered": triggered,
        "category": "Identity & Origin",
        "details": " | ".join(findings) if triggered else "No homoglyph or typosquatted brand lookalikes discovered."
    }


@_rule_contract
def check_urgency_coercion(subject: str, body: str) -> dict:
    """
    RULE-10: Coercive Panic & False Urgency Scrutiny
    Detects psychological pressure designed to force hurried decisions
    (e.g., threats of immediate account deletion, arrest, legal action, or secrecy demands).
    Contributes: +25 pts
    """
    content = normalize_unicode(f"{subject}\n{body}").lower()
    matched = []

    for pattern in COERCION_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            matched.append(pattern.replace(r"\b", "").replace(r"\s*", " "))

    triggered = len(matched) >= 1
    return {
        "rule_id": "RULE-10-URGENCY-COERCION",
        "name": "Coercive Urgency & Pressure",
        "score": 25 if triggered else 0,
        "triggered": triggered,
        "category": "Social Engineering",
        "details": f"Psychological coercion detected ({len(matched)} high-urgency triggers)." if triggered else "Standard conversational pacing without artificial urgency."
    }


@_rule_contract
def check_credential_harvesting(body: str) -> dict:
    """
    RULE-11: Sensitive Identity & Credential Probing
    Flags requests for passwords, M-Pesa PINs, ATM PINs, National ID numbers, KRA PIN credentials,
    or bank card security codes.
    Contributes: +40 pts
    """
    content = normalize_unicode(body).lower()
    matched = []

    for pattern in CREDENTIAL_TARGETS:
        if re.search(pattern, content, re.IGNORECASE):
            matched.append(pattern.replace(r"\b", "").replace(r"\s*", " "))

    has_action = any(verb in content for verb in ["enter", "confirm", "provide", "submit", "reset", "update", "verify", "reply with"])
    triggered = len(matched) >= 1 and (has_action or len(matched) >= 2)

    return {
        "rule_id": "RULE-11-CREDENTIAL-HARVEST",
        "name": "Credential & Sensitive Data Probe",
        "score": 40 if triggered else 0,
        "triggered": triggered,
        "category": "Data Security & Privacy",
        "details": f"Demands disclosure of protected credentials ({', '.join(matched[:3])})." if triggered else "No sensitive identity or PIN submission requests."
    }


@_rule_contract
def check_suspicious_hyperlinks(body: str) -> dict:
    """
    RULE-12: Suspicious Hyperlink Architecture
    Examines embedded links for raw IP addresses, URL shorteners (bit.ly, tinyurl),
    and high-risk top-level domains (.xyz, .top, .buzz, .work, .click).
    Contributes: +30 pts
    """
    urls = extract_links(body)
    findings = []

    for u in urls:
        parsed = urlparse(u)
        host = (parsed.hostname or "").lower()

        # Check for raw IPv4 address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            findings.append(f"Direct IP link target '{host}'")

        # Check for URL shorteners
        if host in POPULAR_SHORTENERS:
            findings.append(f"URL shortener '{host}' disguising destination")

        # Check for high risk TLDs
        for tld in HIGH_RISK_TLDS:
            if host.endswith(tld):
                findings.append(f"Untrusted high-risk TLD '{tld}' on '{host}'")
                break

    triggered = len(findings) > 0
    return {
        "rule_id": "RULE-12-SUSPICIOUS-HYPERLINK",
        "name": "Suspicious Link Anatomy",
        "score": 30 if triggered else 0,
        "triggered": triggered,
        "category": "Network & Technical Signals",
        "details": " | ".join(findings[:2]) if triggered else "All embedded URLs use standard reputable domain conventions."
    }


# Optional stub functions for external threat intelligence (offline by default)
def scan_domain_virustotal(domain: str, api_key: str = None) -> dict:
    return {"status": "disabled", "score": 0, "details": "VirusTotal intelligence is offline."}

def scan_urls_virustotal(urls: list, api_key: str = None) -> dict:
    return {"status": "disabled", "score": 0, "details": "VirusTotal intelligence is offline."}

# Aliases for backward compatibility
check_typosquatting = check_typosquatting_lookalikes

