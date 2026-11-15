# `phish-signal-interceptor`

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Architecture: Pluggable Analyzer](https://img.shields.io/badge/Architecture-IntelOwl%20%7C%20Forta-purple.svg)](#architecture)
[![SIEM Standard: Wazuh / ECS](https://img.shields.io/badge/SIEM-Wazuh%20%7C%20ECS-orange.svg)](#detection-and-alert-schema)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1566.001%20%7C%20T1566.002-red.svg)](https://attack.mitre.org/techniques/T1566/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An open-source, automated Phishing Mail, Domain Posture, and Threat Signal Analyzer engineered for SOC automation, threat intelligence pipelines, and real-time detection engineering.

Designed around the modular analyzer principles of **The Honeynet Project (IntelOwl)** and the deterministic event-monitoring patterns of **Forta Network / Nethermind**, `phish-signal-interceptor` ingests email observables, evaluates sender authentication postures (SPF, DMARC, DKIM), detects header anomalies, and outputs normalized SIEM alerts aligned with **Elastic Common Schema (ECS)** and **Wazuh custom rules**.

---

## Architecture Overview

```mermaid
flowchart TD
    subgraph Ingestion ["Ingestion & Normalization"]
        RAW["Raw Email / EML / Domain Payload"] --> PARSER["RFC 5322 Parser"]
        PARSER --> OBS["EmailObservable (Pydantic Schema)"]
    end

    subgraph Analyzers ["Pluggable Threat Analyzers (IntelOwl / Forta Pattern)"]
        OBS --> A1["DNS & Spoofing Posture Analyzer<br/>(MX, SPF, DMARC via dnspython)"]
        OBS --> A2["Header Alignment Analyzer<br/>(RFC 5322 From vs RFC 5321 Return-Path)"]
        OBS --> A3["Payload & URL Heuristic Analyzer<br/>(Lookalike Domains, IP URLs)"]
    end

    subgraph Evaluation ["Deterministic Triage Engine"]
        A1 --> FINDINGS["DetectionFindings[]"]
        A2 --> FINDINGS
        A3 --> FINDINGS
        FINDINGS --> SCORER["Triage & Scoring Matrix"]
        SCORER --> DECISION{"Confidence Classification"}
        DECISION -->|Score >= 80| QUARANTINE["QUARANTINED_TRUE_POSITIVE"]
        DECISION -->|40 <= Score < 80| FLAGGED["FLAGGED_SUSPICIOUS"]
        DECISION -->|Score < 40| CLEAN["PASSED_CLEAN"]
    end

    subgraph Output ["SIEM & Telemetry Reporters"]
        QUARANTINE --> JSON["Wazuh Custom Alert / ECS Event (JSON)"]
        FLAGGED --> JSON
        CLEAN --> JSON
    end
```

---

## Directory Structure

```text
phish-signal-interceptor/
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions CI (pytest + ruff)
├── docs/
│   └── ENGINEERING_LOG.md       # "By Force, By Fire" decision records
├── src/
│   └── phish_signal/
│       ├── __init__.py
│       ├── schemas/             # Typed observable & finding contracts
│       │   ├── __init__.py
│       │   ├── observable.py    # EmailObservable input definition
│       │   └── finding.py       # DetectionFinding & MITRE mapping
│       ├── analyzers/           # Pluggable detection modules
│       │   ├── __init__.py
│       │   ├── dns_posture.py   # SPF/DMARC resolution & spoofing posture
│       │   └── header_parser.py # RFC 5322/5321 alignment & hops
│       ├── engine/              # Scoring & false-positive triage
│       │   ├── __init__.py
│       │   └── triage.py        # Deterministic scoring matrix
│       └── reporters/           # SIEM output formatters
│           ├── __init__.py
│           └── wazuh_ecs.py     # Wazuh/ECS alert serializer
├── tests/
│   ├── fixtures/                # Spoofed sample emails (.eml)
│   ├── test_schemas.py
│   ├── test_dns_posture.py
│   └── test_triage.py
├── requirements.txt
├── requirements-dev.txt
├── TODO.md                      # Time-boxed sprint & study tracker
└── README.md
```

---

## Core Capabilities

- **Zero-Trust Sender Verification:** Resolves DNS MX, SPF, and DMARC TXT records using `dnspython` to uncover soft-fail bypass configurations (`v=spf1 ~all` combined with missing or `p=none` DMARC).
- **Protocol Alignment Checking:** Flags discrepancies between RFC 5322 human-facing `From:` headers and RFC 5321 envelope `Return-Path` addresses.
- **Deterministic Alert Scoring:** Minimizes false positives by calculating multi-vector risk scores rather than single-heuristic alarms.
- **SIEM-Native Format:** Emits structured JSON alerts enriched with MITRE ATT&CK tactics (`T1566.001`, `T1566.002`) ready for Wazuh rules or Elastic SIEM ingestion.

---

## Milestone 2: DNS & Spoofing Posture Analyzer

The `DNSPostureAnalyzer` evaluates whether an incoming email sender domain leaves recipients defenseless against spoofing attacks due to misconfigured DNS records.

### The Compound Spoofing Flaw (`omniel.com.ng` Logic)

```mermaid
flowchart TD
    DNS["Sender Domain: omniel.com.ng"] --> SPF["SPF: v=spf1 include:_spf.google.com ~all"]
    DNS --> DMARC["DMARC: v=DMARC1; p=none; ..."]
    SPF --> EVAL{"Posture Evaluation"}
    DMARC --> EVAL
    EVAL -->|~all SoftFail + p=none| FLAG["EXPLOITABLE_POSTURE<br/>Severity: HIGH | Confidence: 0.90<br/>MITRE ATT&CK: T1566.002"]
```

When a domain configures `SPF ~all` (SoftFail) and pairs it with `DMARC p=none` (or completely omits DMARC), receiving mail transfer agents (MTAs) like Gmail or Microsoft 365 will **NOT** reject or quarantine spoofed messages. The attacker's unauthorized mail drops straight into the victim's primary inbox.

### Example Analyzer Usage

```python
from phish_signal.analyzers import DNSPostureAnalyzer
from phish_signal.schemas import EmailObservable

analyzer = DNSPostureAnalyzer()

observable = EmailObservable(
    sender_address="accounts@omniel.com.ng",
    recipient_address="victim@enterprise.com",
    subject="Wire Transfer Instructions",
)

findings = analyzer.analyze(observable)
for finding in findings:
    print(finding.model_dump_json(indent=2))
```

### Emitted Finding (JSON Output)

```json
{
  "analyzer_id": "dns_posture",
  "title": "Exploitable Spoofing Posture (SPF SoftFail with DMARC p=none)",
  "description": "Domain 'omniel.com.ng' has SPF set to '~all' but DMARC policy is 'none'. Because neither protocol instructs the receiving server to reject or quarantine unauthorized senders, spoofed emails will land directly in the victim's primary inbox.",
  "severity": "high",
  "confidence": 0.9,
  "mitre_technique_id": "T1566.002",
  "evidence": {
    "domain": "omniel.com.ng",
    "spf_record": "v=spf1 include:_spf.google.com ~all",
    "spf_qualifier": "~all",
    "dmarc_policy": "none"
  },
  "timestamp": "2026-11-14T10:15:00Z"
}
```

---

## Milestone 3: RFC Header & Payload/URL Analyzer

The `HeaderPayloadAnalyzer` inspects email transport headers and body hyperlinks to catch brand impersonation and evasion tactics.

### Detection Heuristics

```mermaid
flowchart TD
    OBS["EmailObservable"] --> H1["From vs Return-Path Mismatch<br/>(RFC 5322 vs RFC 5321)"]
    OBS --> H2["Display Name Brand Impersonation<br/>('PayPal Support' from evil.com)"]
    OBS --> H3["Naked IP Hyperlink in Body<br/>(http://185.220.101.5/login)"]
    H1 --> FINDINGS["DetectionFindings[]"]
    H2 --> FINDINGS
    H3 --> FINDINGS
```

### Example Analyzer Usage

```python
from phish_signal.analyzers import HeaderPayloadAnalyzer
from phish_signal.schemas import EmailObservable

analyzer = HeaderPayloadAnalyzer()

observable = EmailObservable(
    sender_address="alerts@evil-mailer.net",
    sender_display_name="Chase Fraud Department",
    return_path="bounces@another-spoofer.xyz",
    recipient_address="victim@target.com",
    subject="Urgent: Unauthorized Login Detected",
    urls_extracted=["http://198.51.100.44/chase/login.php"],
)

findings = analyzer.analyze(observable)
for finding in findings:
    print(finding.model_dump_json(indent=2))
```
