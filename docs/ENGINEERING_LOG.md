# Engineering Log: `phish-signal-interceptor`

This document records architectural decisions, engineering rationales, and triage trade-offs made during each milestone. Every milestone adds exactly one 3-bullet entry following the structure below.

---

## Log Entries

### [2026-11-12] Setup: GitHub Authentication — Password Auth Deprecated
- **Problem:** `git push` kept returning `remote: Invalid username or token. Password authentication is not supported for Git operations.` even after confirming the password was correct and freshly changed.
- **Root Cause:** GitHub permanently disabled password-based authentication for Git operations in **August 2021** (after a security incident). All Git CLI operations now require a **Personal Access Token (PAT)** instead of your account password. This is not a bug — it's a deliberate security hardening decision by GitHub.
- **Resolution:** Generated a classic PAT at `github.com/settings/tokens` with `repo` scope, used it as the password during `git push`, then ran `git config --global credential.helper store` to cache it locally. Lesson: always check the _error message text carefully_ — it literally says "Password authentication is not supported," which tells you exactly what's wrong.

### [2026-11-13] Milestone 1: Typed Schema Contracts & Decoupled Architecture
- **What We Built:** Implemented `EmailObservable` (RFC 5322/5321 input schema), `DetectionFinding` (standardized analyzer finding output schema mapped to MITRE ATT&CK T1566), `TriageResult` (composite risk aggregation), and 14 unit tests in `tests/test_schemas.py` (100% passing).
- **Why We Designed It This Way:** Decoupled schemas from analyzer modules (mirroring IntelOwl's observable/analyzer boundary and Forta bot contracts) so downstream SIEM exporters and triage matrices never break when new analyzers are plugged in. Enforced immutable, frozen models (`EmailObservable`) so parallel analyzers cannot mutate shared email state.
- **How We Handled False Positives / Incomplete Data:** Transport headers (`return_path`, `message_id`, `reply_to`) are typed as `str | None` with safe defaults; missing headers do not crash ingestion, allowing analyzers to evaluate them as potential spoofing signals. Confidence scores are strictly clamped to `[0.0, 1.0]` to prevent single aberrant heuristics from skewing the composite scoring matrix.

*(More entries will be appended here as each milestone is completed)*

<!--
### [YYYY-MM-DD] Milestone N: <Title>
- **What We Built:** Brief description of modules and functionality implemented.
- **Why We Designed It This Way:** Architectural rationale (e.g., decoupling, typing, standards compliance).
- **How We Handled False Positives / Edge Cases:** Defenses against incomplete data, missing records, or false triggers.
-->
