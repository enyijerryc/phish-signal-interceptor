# Sprint Tracking & State Checkpoint: `phish-signal-interceptor`

> **Academic Rule:** University coursework and 21-unit CGPA priority first.
> **Daily Time-Box:** 1–2 hours per day max (broken into 45–60 min sprints).
> **Target Review Window:** Late December / January (GSoC The Honeynet Project, Outreachy Suricata, Nethermind/Forta).

---

## Current Status Checkpoint
- **Active Milestone:** Milestone 4 (The Triage Engine & Wazuh/ECS Alert Reporter)
- **Current Sub-task:** Implement triage scoring matrix and Wazuh-compatible JSON alert exporter
- **Next Resume Action:** Implement `src/phish_signal/engine/triage.py` and `src/phish_signal/reporters/wazuh_ecs.py`.
- **Last Updated:** 2026-11-15 (Milestone 3 Complete, 40/40 tests passing)

---

## 45–60 Minute Sprint Roadmap

### [x] Milestone 1: Repo Scaffolding & Schema Design
- [x] Directory scaffolding (`src/`, `tests/`, `docs/`)
- [x] Initial `requirements.txt` and `TODO.md` checkpoint setup
- [x] Verification Question: Schema vs. Analyzer decoupling (Answered)
- [x] Implement `src/phish_signal/schemas/observable.py` (`EmailObservable`, strict validation)
- [x] Implement `src/phish_signal/schemas/finding.py` (`DetectionFinding`, ECS & MITRE ATT&CK mapping)
- [x] Unit test suite (`tests/test_schemas.py` — 14/14 tests passing)
- [x] Update `README.md` and log entry in `docs/ENGINEERING_LOG.md`

### [x] Milestone 2: DNS & Spoofing Posture Analyzer (`omniel.com.ng` Logic)
- [x] Concept verification: SPF `~all` / `-all` vs. DMARC `p=none` / `p=quarantine` / `p=reject` (Answered)
- [x] Implement `extract_domain`, `parse_spf_qualifier`, `parse_dmarc_policy`
- [x] Implement `src/phish_signal/analyzers/dns_posture.py` using `dnspython`
- [x] Unit tests for DNS posture with mock DNS answers (`tests/test_dns_posture.py` — 15 tests, all passing)
- [x] Total suite: 29/29 tests passing (100% pass rate)
- [x] Documentation update in `README.md` & `ENGINEERING_LOG.md`

### [x] Milestone 3: RFC Header & Payload/URL Analyzer
- [x] Concept verification: RFC 5322 `From:` vs RFC 5321 `Return-Path` & bounce routing (Answered)
- [x] Implement `check_domain_alignment`, `is_naked_ip_url`, `detect_display_name_deception`
- [x] Implement `src/phish_signal/analyzers/header_analyzer.py`
- [x] Unit tests in `tests/test_header_analyzer.py` (11 tests, all passing)
- [x] Total suite: 40/40 tests passing (100% pass rate)
- [x] Documentation update in `README.md` & `ENGINEERING_LOG.md`

### [ ] Milestone 4: Triage Engine & Wazuh/ECS Alert Output
- [ ] Concept verification: RFC 5322 `From:` vs RFC 5321 `Return-Path` & hop validation
- [ ] Implement `src/phish_signal/analyzers/header_analyzer.py`
- [ ] Implement URL and domain extraction heuristics
- [ ] Documentation update in `README.md` & `ENGINEERING_LOG.md`

### [ ] Milestone 4: Triage Engine & Wazuh/ECS Alert Output
- [ ] Concept verification: Deterministic threat scoring and false-positive reduction
- [ ] Implement `src/phish_signal/engine/triage.py` (Rule router: CLEAN, SUSPICIOUS, QUARANTINED)
- [ ] Implement `src/phish_signal/reporters/wazuh_ecs.py` (Standardized JSON output)
- [ ] Documentation update in `README.md` & `ENGINEERING_LOG.md`

### [ ] Milestone 5: Automated Testing (`pytest`) & GitHub Actions CI
- [ ] Write end-to-end tests with sample spoofed `.eml` fixtures
- [ ] Configure `.github/workflows/ci.yml` (Linting with `ruff`, tests with `pytest`)
- [ ] Generate coverage report & verify green build badge
- [ ] Final portfolio documentation polishing for GSoC/Outreachy/Forta review

---

## Quick Resume Guide (For Busy Course Rep Days)
When you sit down for your 45-minute sprint:
1. Open this file (`TODO.md`).
2. Look at **"Next Resume Action"** above.
3. Complete just that one bullet.
4. Update the "Last Updated" and "Next Resume Action" lines.
5. Close your laptop with zero guilt and 100% focus on classes.
