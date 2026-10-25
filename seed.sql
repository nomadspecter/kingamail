-- ==============================================================================
-- KingaMail Corporate Shield - Seed Data for PostgreSQL / Supabase
-- ==============================================================================

-- 1. SEED ROLES
INSERT INTO "role" (id, name, description) VALUES
(1, 'Employee', 'Standard corporate staff user with access to mailbox and awareness modules.')
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description;

INSERT INTO "role" (id, name, description) VALUES
(2, 'IT Admin', 'Security operations administrator with full triage, incident response, and simulation control.')
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description;

INSERT INTO "role" (id, name, description) VALUES
(3, 'Manager', 'Department head with access to department risk analytics and compliance reporting.')
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description;

SELECT setval('role_id_seq', (SELECT MAX(id) FROM "role"));

-- 2. SEED DEPARTMENTS
INSERT INTO "department" (id, name, code, description) VALUES
(1, 'Information Technology', 'IT', 'Core engineering, cybersecurity, and tech infrastructure')
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, code = EXCLUDED.code;

INSERT INTO "department" (id, name, code, description) VALUES
(2, 'Finance & Accounting', 'FIN', 'Financial planning, payroll, and corporate treasury')
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, code = EXCLUDED.code;

INSERT INTO "department" (id, name, code, description) VALUES
(3, 'Human Resources', 'HR', 'Personnel onboarding, employee benefits, and workplace policy')
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, code = EXCLUDED.code;

INSERT INTO "department" (id, name, code, description) VALUES
(4, 'Sales & Operations', 'OPS', 'Client relations, logistics, and supply chain management')
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, code = EXCLUDED.code;

SELECT setval('department_id_seq', (SELECT MAX(id) FROM "department"));

-- 3. SEED USERS (Hashed Passwords)
-- Passwords:
-- employee@corporate.local -> Employee123!
-- admin@corporate.local    -> Admin123!
-- manager@corporate.local  -> Manager123!
-- bob.miller@corporate.local -> Employee123! (status: compromised, force_password_reset: true)

INSERT INTO "user" (id, email, password_hash, full_name, role_id, department_id, status, force_password_reset) VALUES
(1, 'employee@corporate.local', 'scrypt:32768:8:1$nirZFCpBwXLBGQZA$31d0bf019ad44478f41a582d6877280e019d7289b6bcf4be9274009689965bad6a8a710ae0ee3b2e719a484884cdefd347b76c49a1d4cf3992e104ac51e60bd6', 'Jane Doe', 1, 2, 'active', FALSE)
ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email;

INSERT INTO "user" (id, email, password_hash, full_name, role_id, department_id, status, force_password_reset) VALUES
(2, 'admin@corporate.local', 'scrypt:32768:8:1$6o8zWam0Q8WXNBgC$fa653ca8e759ea6551e6d4cd093b9dd2ec16d2db5614821e6684229012b6707cc6d108a3b6563e47365511bebf466363a307121535db6fc81ff049c584d6693e', 'Alex Rivera', 2, 1, 'active', FALSE)
ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email;

INSERT INTO "user" (id, email, password_hash, full_name, role_id, department_id, status, force_password_reset) VALUES
(3, 'manager@corporate.local', 'scrypt:32768:8:1$fdMhMxJ5iG2dpNNp$3a1578cf4d5b16d3f377e8af28ee78be9aee63c8cb06957e7c7cdcad818023d44c0b3f6af0edd0202e8ae9319c2af8d4ecbb6bc721e4b6e1157cb8347ae841b1', 'Sarah Jenkins', 3, 4, 'active', FALSE)
ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email;

INSERT INTO "user" (id, email, password_hash, full_name, role_id, department_id, status, force_password_reset) VALUES
(4, 'bob.miller@corporate.local', 'scrypt:32768:8:1$nirZFCpBwXLBGQZA$31d0bf019ad44478f41a582d6877280e019d7289b6bcf4be9274009689965bad6a8a710ae0ee3b2e719a484884cdefd347b76c49a1d4cf3992e104ac51e60bd6', 'Bob Miller', 1, 3, 'compromised', TRUE)
ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email;

SELECT setval('user_id_seq', (SELECT MAX(id) FROM "user"));

-- 4. SEED SAMPLE EMAILS (Safe, Suspicious, Quarantined)
INSERT INTO "email" (id, recipient_id, sender, reply_to, subject, body, risk_score, verdict, confidence, indicators, status, is_read, is_reported) VALUES
(1, 1, 'support@microsoft.com', 'support@microsoft.com', 'Scheduled Microsoft 365 Maintenance This Weekend',
 'Hello Team,\n\nPlease be advised that Microsoft will perform scheduled maintenance on our corporate Office 365 tenant this Saturday between 02:00 UTC and 04:00 UTC. No disruption to email service is expected.\n\nBest regards,\nCorporate IT Service Desk',
 0, 'Safe', 'High', '[{"name": "Trusted Domain", "score": 0, "message": "Domain microsoft.com is trusted"}]'::jsonb, 'inbox', TRUE, FALSE),

(2, 1, 'hr-benefits@corporate.local', 'hr-benefits@corporate.local', 'Open Enrollment: Review Your 2026 Health and Dental Benefits',
 'Dear Colleague,\n\nAnnual open enrollment for corporate health, vision, and dental benefits begins next Monday. Please review the employee benefits portal guide on our internal intranet before submitting your elections.\n\nThank you,\nHuman Resources Department',
 0, 'Safe', 'High', '[{"name": "Formatting", "score": 0, "message": "Normal formatting"}]'::jsonb, 'inbox', FALSE, FALSE),

(3, 1, 'billing-notice@unknown-contractor.com', 'billing-notice@unknown-contractor.com', 'Invoice attached for review - Please verify payment details',
 'Hello,\n\nPlease see attachment regarding the outstanding invoice for services rendered last month. Please verify payment details and invoice approved for $12,450. Open attached document immediately.\n\nRegards,\nVendor Accounts',
 45, 'Suspicious', 'Medium', '[{"name": "Attachment Keyword", "score": 25, "message": "Prompt to open attached invoice"}, {"name": "Financial Fraud", "score": 20, "message": "High dollar amount $12,450 referenced"}]'::jsonb, 'inbox', FALSE, FALSE),

(4, 1, 'tracking-update@dhl-express-security.xyz', 'stealth-drop@gmail.com', 'URGENT: Your DHL Package Delivery Has Been Suspended!',
 'URGENT NOTICE!\n\nYour pending package with tracking #DHL-8891244 could not be delivered due to an incorrect delivery address.\n\nACT NOW! Failure to act within 24 hours will result in your package being destroyed.\n\nPlease verify your credit card and billing information immediately at: http://192.168.1.105/secure-login/dhl-verify to pay the $3.50 redelivery fee.\n\nDHL Express Courier Service',
 145, 'Quarantine', 'High', '[{"name": "Urgency", "score": 30, "message": "Urgent act now keywords"}, {"name": "Suspicious Links", "score": 50, "message": "Raw IP address link and lookalike prefix"}, {"name": "Reply-To Mismatch", "score": 35, "message": "Reply-To does not match sender"}]'::jsonb, 'quarantined', FALSE, FALSE),

(5, 1, 'security-alert@micr0soft-support.xyz', 'attacker@scam-collect.top', 'CRITICAL: Your corporate password expires in 2 hours - Confirm now',
 'Dear employee,\n\nYour enterprise single-sign-on password is scheduled to expire today. Your account will be locked immediately if you do not confirm now.\n\nVisit: http://bit.ly/m365-verify-credentials to enter your current password, bank account verification, and PIN number.\n\nCorporate Security Operations',
 155, 'Quarantine', 'High', '[{"name": "Typosquatting", "score": 40, "message": "micr0soft-support.xyz impersonating microsoft.com"}, {"name": "Credential Harvesting", "score": 60, "message": "Requests password, bank account, and PIN"}]'::jsonb, 'quarantined', FALSE, FALSE)
ON CONFLICT (id) DO NOTHING;

SELECT setval('email_id_seq', (SELECT MAX(id) FROM "email"));

-- 5. SEED TRAINING MODULES
INSERT INTO "training_module" (id, title, description, category, estimated_minutes, difficulty, content) VALUES
(1, 'Recognizing Social Engineering & Artificial Urgency',
 'Learn how threat actors exploit psychological pressure, false deadlines, and panic triggers.',
 'Phishing Awareness', 10, 'Beginner',
 '### The Psychology of Urgency\n\nAttackers often manipulate emotions such as fear, curiosity, or greed. Phrases like "Account Suspended in 24 Hours" are designed to bypass rational skepticism. Always pause and verify.')
ON CONFLICT (id) DO NOTHING;

INSERT INTO "training_module" (id, title, description, category, estimated_minutes, difficulty, content) VALUES
(2, 'Spear Phishing & Executive Impersonation (CEO Fraud)',
 'Understand targeted Business Email Compromise (BEC) and wire transfer spoofing schemes.',
 'Advanced Threats', 15, 'Intermediate',
 '### Defending Against Executive Spoofing\n\nBusiness Email Compromise occurs when an attacker impersonates a C-level executive requesting secret gift cards or urgent payments. Never execute out-of-band wire transfers without voice confirmation.')
ON CONFLICT (id) DO NOTHING;

SELECT setval('training_module_id_seq', (SELECT MAX(id) FROM "training_module"));

-- 6. SEED BLOCKED SENDER
INSERT INTO "blocked_sender" (id, sender_value, blocked_by_user_id, reason) VALUES
(1, 'tracking-update@dhl-express-security.xyz', 2, 'Confirmed active phishing credential harvester')
ON CONFLICT (id) DO NOTHING;

SELECT setval('blocked_sender_id_seq', (SELECT MAX(id) FROM "blocked_sender"));
