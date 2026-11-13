"""Tests for EmailObservable and DetectionFinding schema validation.

These tests verify that:
    1. Valid phishing email data passes Pydantic validation.
    2. Invalid/missing required fields are rejected with clear errors.
    3. DetectionFinding enforces MITRE ATT&CK ID format (T####.###).
    4. Confidence scores are clamped to [0.0, 1.0].
    5. EmailObservable is frozen (immutable after creation).
"""

import pytest
from pydantic import ValidationError

from phish_signal.schemas import (
    DetectionFinding,
    EmailObservable,
    Severity,
    TriageResult,
    TriageVerdict,
)


# ─── EmailObservable Tests ───────────────────────────────────────────


class TestEmailObservable:
    """Test suite for the EmailObservable input schema."""

    def test_valid_minimal_observable(self):
        """Minimum required fields should create a valid observable."""
        obs = EmailObservable(
            sender_address="attacker@evil.com",
            recipient_address="victim@example.com",
            subject="Urgent: Verify your account",
        )
        assert obs.sender_address == "attacker@evil.com"
        assert obs.recipient_address == "victim@example.com"
        assert obs.subject == "Urgent: Verify your account"
        # Optional fields default to None or empty lists
        assert obs.return_path is None
        assert obs.reply_to is None
        assert obs.urls_extracted == []
        assert obs.attachments == []

    def test_valid_full_observable(self):
        """All fields populated should create a valid observable."""
        obs = EmailObservable(
            sender_address="security@paypa1.com",
            sender_display_name="PayPal Security Team",
            return_path="bounce@evil-domain.xyz",
            reply_to="reply@evil-domain.xyz",
            recipient_address="victim@example.com",
            subject="Your account has been compromised",
            message_id="<fake-id-12345@evil-domain.xyz>",
            received_headers=[
                "from mail.evil-domain.xyz (1.2.3.4) by mx.example.com"
            ],
            body_plain="Click here to verify: http://paypa1-secure.com/login",
            urls_extracted=["http://paypa1-secure.com/login"],
            attachments=["invoice.pdf"],
        )
        assert obs.sender_display_name == "PayPal Security Team"
        assert obs.return_path == "bounce@evil-domain.xyz"
        assert len(obs.received_headers) == 1
        assert len(obs.urls_extracted) == 1
        assert obs.attachments == ["invoice.pdf"]

    def test_missing_required_field_raises(self):
        """Missing sender_address should raise ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            EmailObservable(
                recipient_address="victim@example.com",
                subject="Test",
            )
        assert "sender_address" in str(exc_info.value)

    def test_invalid_email_format_raises(self):
        """Invalid email format should raise ValidationError."""
        with pytest.raises(ValidationError):
            EmailObservable(
                sender_address="not-an-email",
                recipient_address="victim@example.com",
                subject="Test",
            )

    def test_observable_is_immutable(self):
        """EmailObservable should be frozen (immutable after creation)."""
        obs = EmailObservable(
            sender_address="test@example.com",
            recipient_address="victim@example.com",
            subject="Test",
        )
        with pytest.raises(ValidationError):
            obs.subject = "Modified subject"


# ─── DetectionFinding Tests ──────────────────────────────────────────


class TestDetectionFinding:
    """Test suite for the DetectionFinding output schema."""

    def test_valid_finding(self):
        """A well-formed finding should pass validation."""
        finding = DetectionFinding(
            analyzer_id="dns_posture",
            title="SPF SoftFail with DMARC p=none",
            description="Sender domain allows spoofed emails through.",
            severity=Severity.HIGH,
            confidence=0.85,
            mitre_technique_id="T1566.002",
            evidence={
                "spf_record": "v=spf1 ~all",
                "dmarc_policy": "p=none",
            },
        )
        assert finding.analyzer_id == "dns_posture"
        assert finding.severity == Severity.HIGH
        assert finding.confidence == 0.85
        assert finding.mitre_technique_id == "T1566.002"
        assert "spf_record" in finding.evidence

    def test_confidence_below_zero_raises(self):
        """Confidence score below 0.0 should be rejected."""
        with pytest.raises(ValidationError):
            DetectionFinding(
                analyzer_id="test",
                title="Test",
                description="Test",
                severity=Severity.LOW,
                confidence=-0.1,
                mitre_technique_id="T1566.001",
            )

    def test_confidence_above_one_raises(self):
        """Confidence score above 1.0 should be rejected."""
        with pytest.raises(ValidationError):
            DetectionFinding(
                analyzer_id="test",
                title="Test",
                description="Test",
                severity=Severity.LOW,
                confidence=1.5,
                mitre_technique_id="T1566.001",
            )

    def test_invalid_mitre_id_raises(self):
        """Malformed MITRE ATT&CK ID should be rejected."""
        with pytest.raises(ValidationError):
            DetectionFinding(
                analyzer_id="test",
                title="Test",
                description="Test",
                severity=Severity.LOW,
                confidence=0.5,
                mitre_technique_id="INVALID",
            )

    def test_valid_mitre_id_without_subtechnique(self):
        """MITRE ID without sub-technique (e.g., T1566) should be valid."""
        finding = DetectionFinding(
            analyzer_id="test",
            title="Test",
            description="Test",
            severity=Severity.LOW,
            confidence=0.5,
            mitre_technique_id="T1566",
        )
        assert finding.mitre_technique_id == "T1566"

    def test_timestamp_auto_generated(self):
        """Timestamp should be automatically set to UTC if not provided."""
        finding = DetectionFinding(
            analyzer_id="test",
            title="Test",
            description="Test",
            severity=Severity.LOW,
            confidence=0.5,
            mitre_technique_id="T1566.001",
        )
        assert finding.timestamp is not None


# ─── TriageResult Tests ──────────────────────────────────────────────


class TestTriageResult:
    """Test suite for the TriageResult composite output."""

    def test_clean_verdict(self):
        """A clean triage result with no findings should be valid."""
        result = TriageResult(
            observable_id="<msg-001@example.com>",
            verdict=TriageVerdict.PASSED_CLEAN,
            composite_score=10.0,
            findings=[],
        )
        assert result.verdict == TriageVerdict.PASSED_CLEAN
        assert result.composite_score == 10.0
        assert len(result.findings) == 0

    def test_quarantined_with_findings(self):
        """A quarantined result with high-confidence findings."""
        finding = DetectionFinding(
            analyzer_id="dns_posture",
            title="SPF SoftFail",
            description="Domain allows spoofing.",
            severity=Severity.HIGH,
            confidence=0.9,
            mitre_technique_id="T1566.002",
        )
        result = TriageResult(
            observable_id="<msg-002@example.com>",
            verdict=TriageVerdict.QUARANTINED_TRUE_POSITIVE,
            composite_score=92.0,
            findings=[finding],
        )
        assert result.verdict == TriageVerdict.QUARANTINED_TRUE_POSITIVE
        assert len(result.findings) == 1
        assert result.findings[0].confidence == 0.9

    def test_composite_score_bounds(self):
        """Composite score outside 0–100 should be rejected."""
        with pytest.raises(ValidationError):
            TriageResult(
                observable_id="test",
                verdict=TriageVerdict.PASSED_CLEAN,
                composite_score=150.0,
            )
