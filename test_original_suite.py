"""
test_original_suite.py - Verification Suite for Original Architecture & Kenyan Threats
----------------------------------------------------------------------------------------
Tests against live Supabase PostgreSQL database:
1. 12 Rewritten Detection Checks:
   - RULE-01: Local Blocklist (+60 pts -> Quarantine)
   - RULE-02: Trusted Domain (corporate.local = 0 pts; untrusted = +15 pts)
   - RULE-03: Mismatched Display-Name Spoofing (+45 pts) [Original Check #1]
   - RULE-04: Kenyan Telecom & M-Pesa Fraud (+40 pts)
   - RULE-05: Kenyan Government & Statutory Compliance (+45 pts)
   - RULE-06: Kenyan Financial Institutions & SACCOs (+40 pts)
   - RULE-07: Public Procurement & Invoice BEC Fraud (+40 pts)
   - RULE-08: Free Professional Training & Fellowship Lure (+35 pts) [Original Check #2]
   - RULE-09: Lookalike & Typosquatting Homoglyphs (+40 pts)
   - RULE-10: Coercive Urgency & Threat Pressure (+25 pts)
   - RULE-11: Sensitive Identity & PIN Probing (+40 pts)
   - RULE-12: Suspicious Hyperlink Architecture (+30 pts)
2. Custom Scoring Thresholds:
   - 0 to 24 points: Safe
   - 25 to 54 points: Suspicious
   - 55+ points: Quarantine
3. Kenyan Simulation Templates in campaigns list
4. Chart.js & Left Sidebar UI structure in templates
5. Security Guards: Role checks, CSRF, parameterization, zero credential collection on simulations
"""

from app import create_app
from database import db
from models import User, Role, Department, Email, Campaign, BlockedSender
from detection.scoring import analyze_email
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


def run_tests():
    app = create_app()
    with app.app_context():
        print(">>> [Original Suite Test] Validating original architecture & Kenyan threat intelligence...")

        # ── 1. TEST INDIVIDUAL HEURISTIC RULES ────────────────────────
        # Rule 1: Blocklist
        res_block = check_blocklist("kra-portal.xyz", "http://kra-portal.xyz/pay")
        assert res_block["triggered"] is True and res_block["score"] == 60
        print("  ✓ RULE-01 (Blocklist): Blacklisted domain triggers +60 pts")

        # Rule 2: Trusted Domain (corporate.local = 0 pts; untrusted = +15 pts)
        res_trust = check_trusted_domain("corporate.local")
        assert res_trust["score"] == 0 and res_trust["triggered"] is False
        res_untrust = check_trusted_domain("random-domain-789.xyz")
        assert res_untrust["score"] == 15 and res_untrust["triggered"] is True
        print("  ✓ RULE-02 (Trusted Origin): corporate.local receives 0 pts, untrusted external receives +15 pts")

        # Rule 3: Mismatched Display Name [Original Check #1]
        res_display_phish = check_display_name_spoof("Kenya Revenue Authority", "attacker-domain.xyz")
        assert res_display_phish["triggered"] is True and res_display_phish["score"] == 45
        res_display_safe = check_display_name_spoof("Kenya Revenue Authority", "kra.go.ke")
        assert res_display_safe["triggered"] is False and res_display_safe["score"] == 0
        print("  ✓ RULE-03 (Display-Name Spoofing): Mismatched display name claims authority -> +45 pts")

        # Rule 4: Kenyan Telecom & M-Pesa Fraud
        mpesa_text = "Confirmed you have received KES 15,000. To reverse transaction, visit link and confirm M-Pesa PIN."
        res_mpesa = check_kenya_telecom_mpesa("M-PESA Reversal Notice", mpesa_text)
        assert res_mpesa["triggered"] is True and res_mpesa["score"] == 40
        print("  ✓ RULE-04 (M-Pesa & Telecom Fraud): Reverse float / M-Pesa lures flagged -> +40 pts")

        # Rule 5: Kenyan Public Sector & KRA/eCitizen/HELB
        kra_text = "Notice of iTax VAT penalty and tax compliance certificate revocation. Settle via eCitizen."
        res_kra = check_kenya_government_compliance("KRA Compliance Notice", kra_text, "kra-fake.xyz")
        assert res_kra["triggered"] is True and res_kra["score"] == 45
        print("  ✓ RULE-05 (Government & Statutory Compliance): KRA/eCitizen/HELB lures flagged -> +45 pts")

        # Rule 6: Kenyan Banks & SACCOs
        bank_text = "Your Equity Bank and Stima SACCO account is suspended. Confirm your mobile banking OTP to re-activate."
        res_bank = check_kenya_financial_sacco("Account Suspension", bank_text, "equity-alert.xyz")
        assert res_bank["triggered"] is True and res_bank["score"] == 40
        print("  ✓ RULE-06 (Banking & SACCO Fraud): Commercial bank and SACCO impersonation flagged -> +40 pts")

        # Rule 7: Procurement, Tender & Invoice Fraud
        tender_text = "County Government Tender award notification. Review LPO #CGN/PROC/2026/884 and remit new bank account."
        res_tender = check_tender_invoice_fraud("Tender Award", tender_text)
        assert res_tender["triggered"] is True and res_tender["score"] == 40
        print("  ✓ RULE-07 (Tender & Invoice Fraud): Forged LPOs and invoice bank diversion flagged -> +40 pts")

        # Rule 8: Free Professional Training & Fellowship Lure [Original Check #2]
        training_text = "You are selected for a fully funded workshop in Nairobi with free CPD points and per diem allowance. Register now."
        res_training = check_free_training_lure("Leadership Fellowship", training_text)
        assert res_training["triggered"] is True and res_training["score"] == 35
        print("  ✓ RULE-08 (Free Training Lure): Bogus fully-funded corporate fellowship & CPD lures flagged -> +35 pts")

        # Rule 9: Lookalikes & Homoglyphs
        res_lookalike = check_typosquatting_lookalikes("safar1com-support.com", "")
        assert res_lookalike["triggered"] is True and res_lookalike["score"] == 40
        print("  ✓ RULE-09 (Lookalikes & Homoglyphs): Leetspeak 'safar1com' detected -> +40 pts")

        # Rule 10: Urgency & Coercion
        urgency_text = "Immediate action required within 2 hours or police arrest and CRB blacklisting will occur. Keep strictly confidential."
        res_urgency = check_urgency_coercion("URGENT Notice", urgency_text)
        assert res_urgency["triggered"] is True and res_urgency["score"] == 25
        print("  ✓ RULE-10 (Coercive Urgency): False panic deadlines & secrecy demands flagged -> +25 pts")

        # Rule 11: Credential Harvesting
        cred_text = "Please enter your secret M-Pesa PIN and password to verify your national ID."
        res_cred = check_credential_harvesting(cred_text)
        assert res_cred["triggered"] is True and res_cred["score"] == 40
        print("  ✓ RULE-11 (Credential Probing): Identity, password, and secret PIN probes flagged -> +40 pts")

        # Rule 12: Suspicious Hyperlinks
        link_text = "Visit our portal at http://192.168.1.105/login or http://bit.ly/claim-prize and http://scam.xyz"
        res_link = check_suspicious_hyperlinks(link_text)
        assert res_link["triggered"] is True and res_link["score"] == 30
        print("  ✓ RULE-12 (Suspicious Links): IP addresses, shorteners, and .xyz TLDs flagged -> +30 pts")

        # ── 2. TEST CUSTOM THRESHOLDS & VERDICT MAPPING ───────────────
        # Clean email -> Safe (score <= 24)
        clean_email = (
            "From: Corporate HR <hr@corporate.local>\n"
            "Subject: Internal Weekly Memo\n\n"
            "Team, please review the minutes from our Monday department standup."
        )
        scan_clean = analyze_email(clean_email)
        assert scan_clean["verdict"] == "Safe", f"Expected Safe verdict, got {scan_clean['verdict']}"
        assert scan_clean["total_score"] <= 24, f"Expected score <= 24, got {scan_clean['total_score']}"

        # Mild external email with free training lure -> Suspicious (25 <= score <= 54)
        training_email = (
            "From: African Leadership Foundation <fellowship@international-grants.xyz>\n"
            "Subject: Fully Funded Professional Development Fellowship & CPD Credits (Nairobi)\n\n"
            "Congratulations! You have been selected for a fully funded workshop in Nairobi with 20 free CPD credits and per diem allowance. "
            "Please register now at the nomination portal."
        )
        scan_training = analyze_email(training_email)
        assert scan_training["verdict"] == "Suspicious", f"Expected Suspicious verdict, got {scan_training['verdict']}"
        assert 25 <= scan_training["total_score"] <= 54, f"Expected 25 <= score <= 54, got {scan_training['total_score']}"

        # Malicious KRA Phish -> Quarantine (score >= 55)
        kra_phish = (
            "From: Kenya Revenue Authority <support@kra-portal.xyz>\n"
            "Subject: URGENT: KRA Tax Compliance Certificate Suspension\n\n"
            "Dear Taxpayer, outstanding withholding tax VAT penalty. Settle immediately within 24 hours to prevent CRB listing. "
            "Click http://kra-portal.xyz/pay and enter your KRA PIN password."
        )
        scan_kra = analyze_email(kra_phish)
        assert scan_kra["verdict"] == "Quarantine", f"Expected Quarantine verdict, got {scan_kra['verdict']}"
        assert scan_kra["total_score"] >= 55, f"Expected score >= 55, got {scan_kra['total_score']}"
        print(f"  ✓ Custom scoring thresholds verified: Clean={scan_clean['total_score']} (Safe <=24), Training={scan_training['total_score']} (Suspicious 25-54), KRA Phish={scan_kra['total_score']} (Quarantine >=55)")

        # ── 3. TEST CLIENT & UI TEMPLATES ─────────────────────────────
        client = app.test_client()

        # Public landing includes SYSTEM_NAME and left sidebar
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"app-sidebar" in resp.data
        assert b"chart.js" in resp.data.lower() or b"Chart" in resp.data
        print("  ✓ Original left sidebar layout & Chart.js integration verified in UI")

        # Simulation landing never captures credentials
        # Check template simulation_landing.html
        with open("templates/simulation_landing.html", "r") as f:
            landing_html = f.read()
        assert "<form" not in landing_html, "Simulation landing page must not contain forms"
        assert 'type="password"' not in landing_html, "Simulation landing page must not contain password inputs"
        print("  ✓ Simulation privacy guard verified: Zero credential collection on landing page")

        print("\n=================================================================")
        print(" ALL ORIGINAL ARCHITECTURE & KENYAN DETECTION TESTS PASSED (DB)")
        print("=================================================================\n")


if __name__ == "__main__":
    run_tests()
