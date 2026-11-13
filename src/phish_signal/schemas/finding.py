"""
DetectionFinding: The standardized output schema for all analyzers.

Every analyzer in phish-signal-interceptor — whether it checks DNS posture,
RFC header alignment, or URL heuristics — MUST return one or more
DetectionFinding objects. This is the shared contract that decouples
analyzers from the triage engine and SIEM reporters.

Design Rationale:
    - A single, uniform finding schema means the triage engine and Wazuh/ECS
      exporter never need to know which analyzer produced a finding.
    - New analyzers can be added by any contributor without modifying
      downstream code (reporters, engine) — they just return DetectionFinding.
    - Each finding carries a MITRE ATT&CK technique ID so SOC analysts can
      immediately map the detection to the ATT&CK framework.
    - Confidence scores (0.0–1.0) allow the triage engine to combine
      multiple weak signals into a strong composite verdict, reducing
      false positives from any single analyzer.

References:
    - MITRE ATT&CK T1566.001: Spearphishing Attachment
    - MITRE ATT&CK T1566.002: Spearphishing Link
    - MITRE ATT&CK T1566.003: Spearphishing via Service
    - Elastic Common Schema (ECS): event.kind, event.category, event.outcome
    - Wazuh Custom Rules: rule.id, rule.level, rule.description
"""

from datetime import datetime, timezone
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Alert severity levels aligned with Wazuh rule levels and ECS event.severity."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TriageVerdict(StrEnum):
    """Final classification after all analyzers have reported.

    These verdicts map to SOC analyst actions:
        - QUARANTINED_TRUE_POSITIVE: Block/quarantine, high-confidence phishing.
        - FLAGGED_SUSPICIOUS: Escalate to analyst for manual review.
        - PASSED_CLEAN: No threat indicators found, deliver normally.
    """

    QUARANTINED_TRUE_POSITIVE = "QUARANTINED_TRUE_POSITIVE"
    FLAGGED_SUSPICIOUS = "FLAGGED_SUSPICIOUS"
    PASSED_CLEAN = "PASSED_CLEAN"


class DetectionFinding(BaseModel):
    """A single threat signal produced by an analyzer.

    Attributes:
        analyzer_id: Unique identifier of the analyzer that produced this
            finding (e.g., 'dns_posture', 'header_alignment', 'url_heuristic').
        title: Short, human-readable title of the detection
            (e.g., 'SPF SoftFail with DMARC p=none').
        description: Detailed explanation of what was detected and why
            it is suspicious.
        severity: Alert severity level (low, medium, high, critical).
        confidence: Confidence score from 0.0 (no confidence) to 1.0
            (absolute certainty). The triage engine uses this to weight
            findings when calculating the composite score.
        mitre_technique_id: MITRE ATT&CK technique identifier
            (e.g., 'T1566.001' for spearphishing attachment,
            'T1566.002' for spearphishing link).
        evidence: Dictionary of key-value pairs showing the raw data
            that triggered this finding (e.g., {'spf_record': 'v=spf1 ~all',
            'dmarc_policy': 'none'}). This is critical for analyst review
            and false-positive triage.
        timestamp: UTC timestamp of when the finding was generated.
    """

    analyzer_id: str = Field(
        ...,
        description="Unique identifier of the producing analyzer.",
    )
    title: str = Field(
        ...,
        description="Short human-readable detection title.",
    )
    description: str = Field(
        ...,
        description="Detailed explanation of the detected threat signal.",
    )
    severity: Severity = Field(
        ...,
        description="Alert severity (low, medium, high, critical).",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score: 0.0 (none) to 1.0 (certain).",
    )
    mitre_technique_id: str = Field(
        ...,
        pattern=r"^T\d{4}(\.\d{3})?$",
        description="MITRE ATT&CK technique ID (e.g., 'T1566.001').",
    )
    evidence: dict[str, str] = Field(
        default_factory=dict,
        description="Raw data key-value pairs that triggered this finding.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of finding generation.",
    )

    model_config = {
        "str_strip_whitespace": True,
        "json_schema_extra": {
            "examples": [
                {
                    "analyzer_id": "dns_posture",
                    "title": "SPF SoftFail with DMARC p=none",
                    "description": (
                        "The sender domain has an SPF record ending in '~all' "
                        "(SoftFail) combined with a DMARC policy of 'p=none'. "
                        "This configuration allows spoofed emails to pass "
                        "through without being rejected or quarantined."
                    ),
                    "severity": "high",
                    "confidence": 0.85,
                    "mitre_technique_id": "T1566.002",
                    "evidence": {
                        "spf_record": "v=spf1 include:_spf.google.com ~all",
                        "dmarc_policy": "p=none",
                        "sender_domain": "omniel.com.ng",
                    },
                }
            ]
        },
    }


class TriageResult(BaseModel):
    """Composite triage output combining all analyzer findings.

    This is the final output of the triage engine — it aggregates
    DetectionFindings from all analyzers, computes a composite risk
    score, and assigns a verdict. The Wazuh/ECS reporter serializes
    this into a SIEM-ready JSON alert.

    Attributes:
        observable_id: Reference to the analyzed email (typically the
            Message-ID or a generated hash).
        verdict: Final classification (QUARANTINED, FLAGGED, or CLEAN).
        composite_score: Weighted aggregate score (0–100) derived from
            all individual finding confidence scores.
        findings: List of all DetectionFinding objects from every analyzer.
        analyzed_at: UTC timestamp of when triage completed.
    """

    observable_id: str = Field(
        ...,
        description="Identifier for the analyzed email observable.",
    )
    verdict: TriageVerdict = Field(
        ...,
        description="Final triage classification.",
    )
    composite_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Weighted composite risk score (0–100).",
    )
    findings: list[DetectionFinding] = Field(
        default_factory=list,
        description="All detection findings from every analyzer.",
    )
    analyzed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of triage completion.",
    )
