"""Phish-Signal-Interceptor schema contracts.

Public API:
    EmailObservable  — Validated input schema (the "evidence bag")
    DetectionFinding — Standardized output from any analyzer
    TriageResult     — Composite triage verdict with all findings
    Severity         — Alert severity enum (low → critical)
    TriageVerdict    — Final classification enum (CLEAN / SUSPICIOUS / QUARANTINED)
"""

from phish_signal.schemas.finding import (
    DetectionFinding,
    Severity,
    TriageResult,
    TriageVerdict,
)
from phish_signal.schemas.observable import EmailObservable

__all__ = [
    "DetectionFinding",
    "EmailObservable",
    "Severity",
    "TriageResult",
    "TriageVerdict",
]
