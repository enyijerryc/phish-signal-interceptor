# Engineering Log: `phish-signal-interceptor`

This document records the real engineering decisions, mistakes, and solutions made during each milestone. Every milestone has a simple 3-bullet entry explaining what was built, why we made that choice, and how we avoided false alarms.

---

## Log Entries

### [2026-11-12] Setup: Fixing GitHub Password Authentication
- **Problem:** When trying to push code with `git push`, GitHub kept failing with `Password authentication is not supported for Git operations`, even after resetting the password.
- **Root Cause:** GitHub stopped accepting account passwords for terminal Git operations in August 2021. You have to use a Personal Access Token (PAT) instead.
- **Resolution:** Created a personal access token with repo permissions under GitHub Developer Settings, used that token as the password, and cached it with `git config credential.helper store`.

### [2026-11-13] Milestone 1: Building the Input & Output Data Schemas
- **What We Built:** Created `EmailObservable` (the model that holds incoming email data) and `DetectionFinding` (the standard format for alerts) using Pydantic, backed by 14 unit tests in `tests/test_schemas.py`.
- **Why We Designed It This Way:** We separated the data format from the analyzer logic (the same way IntelOwl and Forta do). This means new contributors can write new detection checks without touching or breaking our alert system. We also locked the email data as read-only (`frozen=True`) so no analyzer can accidentally edit or contaminate the original email evidence.
- **How We Handled Incomplete Data & Edge Cases:** If an email is missing headers like `Return-Path` or `Reply-To`, we set them to `None` instead of crashing. This lets our analyzers see that a header is missing and decide if that looks suspicious. We also limited confidence scores strictly between 0.0 and 1.0 so no single test can throw off the overall risk score.

### [2026-11-14] Milestone 2: DNS & Spoofing Posture Analyzer (Detecting the omniel.com.ng Flaw)
- **What We Built:** Built `DNSPostureAnalyzer` (`src/phish_signal/analyzers/dns_posture.py`) using `dnspython`. It looks up a domain's MX, SPF, and DMARC records to catch email spoofing vulnerabilities. Added 15 new tests in `tests/test_dns_posture.py` (total 29/29 tests passing).
- **Why We Designed It This Way:** We used a Python DNS library (`dnspython`) instead of running terminal commands like `dig` so the code works cleanly on any operating system. We built it to accept mock DNS answers during tests, which means our automated tests run in less than half a second without needing an active internet connection.
- **How We Handled Incomplete Data & Edge Cases:** If a domain has no DNS records or the lookup times out, our code catches the error and returns an empty list instead of crashing the program. A secure domain with strict SPF (`-all`) and DMARC (`reject`) produces zero warnings (no false positives), while a domain using SoftFail (`~all`) with DMARC `none` (like `omniel.com.ng`) correctly triggers a high-severity warning because unauthorized emails will land right in the user's inbox.

### [2026-11-15] Milestone 3: RFC Header Alignment & Payload/URL Analyzer
- **What We Built:** Implemented `HeaderPayloadAnalyzer` (`src/phish_signal/analyzers/header_analyzer.py`) with 11 new tests in `tests/test_header_analyzer.py` (total 40/40 tests passing). It checks for mismatches between the visible `From:` and envelope `Return-Path` domains, detects brand impersonation in display names, and catches raw IP hyperlinks in the body.
- **Why We Designed It This Way:** Attackers frequently bypass SPF by sending mail from their own server (making `Return-Path` pass SPF) while displaying a trusted brand like Chase or PayPal in the `From:` header. Comparing these two addresses is a high-signal detection method. We also check URLs for naked IP addresses because attackers use raw IPs (like `http://185.220.101.5/login`) to bypass domain reputation blocklists.
- **How We Handled Incomplete Data & Edge Cases:** If an email has no `Return-Path`, we don't assume it is malicious; we skip the check to prevent false alarms on internal emails. For display name checks, if a sender actually owns the domain (e.g. display name "PayPal Support" from `service@paypal.com`), our code recognizes it is legitimate and avoids false positive alerts.

*(More entries will be appended here as each milestone is completed)*
