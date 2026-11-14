"""Tests for the DNS & Spoofing Posture Analyzer (Milestone 2).

These tests verify:
    1. extract_domain correctly parses, strips, and lowercases domains.
    2. parse_spf_qualifier extracts ~all, -all, +all correctly.
    3. parse_dmarc_policy extracts none, quarantine, reject.
    4. DNSPostureAnalyzer flags the omniel.com.ng vulnerability (SPF ~all + DMARC p=none).
    5. DNSPostureAnalyzer passes a hardened domain (SPF -all + DMARC p=reject).
"""

from unittest.mock import MagicMock

import pytest

from phish_signal.analyzers.dns_posture import (
    DNSPostureAnalyzer,
    extract_domain,
    parse_dmarc_policy,
    parse_spf_qualifier,
)
from phish_signal.schemas.finding import Severity
from phish_signal.schemas.observable import EmailObservable


# ─── Unit Tests: Helper Functions ────────────────────────────────────


class TestExtractDomain:
    """Tests for the extract_domain helper function."""

    def test_extract_clean_domain(self):
        assert extract_domain("user@example.com") == "example.com"

    def test_extract_uppercase_and_spaces(self):
        assert extract_domain("  Admin@OMNIEL.COM.NG  ") == "omniel.com.ng"

    def test_missing_at_symbol_raises_value_error(self):
        with pytest.raises(ValueError, match="missing '@'"):
            extract_domain("not-an-email")

    def test_empty_domain_raises_value_error(self):
        with pytest.raises(ValueError, match="empty domain"):
            extract_domain("user@")


class TestParseSPFQualifier:
    """Tests for SPF qualifier parsing."""

    def test_softfail_qualifier(self):
        spf = "v=spf1 include:_spf.google.com ~all"
        assert parse_spf_qualifier(spf) == "~all"

    def test_hardfail_qualifier(self):
        spf = "v=spf1 ip4:192.168.1.1 -all"
        assert parse_spf_qualifier(spf) == "-all"

    def test_pass_qualifier(self):
        spf = "v=spf1 +all"
        assert parse_spf_qualifier(spf) == "+all"

    def test_missing_qualifier(self):
        spf = "v=spf1 include:_spf.google.com"
        assert parse_spf_qualifier(spf) == "none"


class TestParseDMARCPolicy:
    """Tests for DMARC p= policy parsing."""

    def test_policy_none(self):
        dmarc = "v=DMARC1; p=none; sp=none; rua=mailto:dmarc@example.com"
        assert parse_dmarc_policy(dmarc) == "none"

    def test_policy_quarantine(self):
        dmarc = "v=DMARC1; p=quarantine; pct=100"
        assert parse_dmarc_policy(dmarc) == "quarantine"

    def test_policy_reject(self):
        dmarc = "v=DMARC1; p=reject; aspf=s"
        assert parse_dmarc_policy(dmarc) == "reject"

    def test_missing_policy(self):
        dmarc = "v=DMARC1; rua=mailto:dmarc@example.com"
        assert parse_dmarc_policy(dmarc) == "missing"


# ─── Integration Tests: DNSPostureAnalyzer with Mock DNS ─────────────


class TestDNSPostureAnalyzer:
    """Tests for the complete DNS Posture Analyzer using mocked DNS lookups."""

    def test_vulnerable_domain_omniel_pattern(self):
        """Simulates omniel.com.ng: SPF ~all + DMARC p=none + valid MX."""
        analyzer = DNSPostureAnalyzer()

        # Mock the resolver methods
        analyzer.resolve_mx = MagicMock(return_value=["mail.omniel.com.ng"])
        analyzer.resolve_txt = MagicMock(
            side_effect=lambda domain: (
                ["v=spf1 include:_spf.google.com ~all"]
                if not domain.startswith("_dmarc")
                else ["v=DMARC1; p=none; rua=mailto:reports@omniel.com.ng"]
            )
        )

        obs = EmailObservable(
            sender_address="admin@omniel.com.ng",
            recipient_address="victim@target.com",
            subject="Invoice Overdue Notice",
        )

        findings = analyzer.analyze(obs)

        # Should flag the critical exploitable posture
        vuln_finding = next(
            (f for f in findings if "SPF SoftFail with DMARC p=none" in f.title),
            None,
        )
        assert vuln_finding is not None
        assert vuln_finding.severity == Severity.HIGH
        assert vuln_finding.confidence == 0.90
        assert vuln_finding.mitre_technique_id == "T1566.002"
        assert vuln_finding.evidence["spf_qualifier"] == "~all"
        assert vuln_finding.evidence["dmarc_policy"] == "none"

    def test_secure_hardened_domain_produces_no_vulnerabilities(self):
        """Simulates a secure domain: SPF -all + DMARC p=reject + valid MX."""
        analyzer = DNSPostureAnalyzer()

        analyzer.resolve_mx = MagicMock(return_value=["mail.securecorp.com"])
        analyzer.resolve_txt = MagicMock(
            side_effect=lambda domain: (
                ["v=spf1 include:_spf.google.com -all"]
                if not domain.startswith("_dmarc")
                else ["v=DMARC1; p=reject; pct=100"]
            )
        )

        obs = EmailObservable(
            sender_address="alerts@securecorp.com",
            recipient_address="victim@target.com",
            subject="Legitimate Security Alert",
        )

        findings = analyzer.analyze(obs)
        # A hardened domain should trigger ZERO spoofing findings
        assert len(findings) == 0

    def test_missing_spf_and_dmarc_completely(self):
        """Domain with no SPF and no DMARC records at all."""
        analyzer = DNSPostureAnalyzer()

        analyzer.resolve_mx = MagicMock(return_value=["mx.unconfigured.com"])
        analyzer.resolve_txt = MagicMock(return_value=[])

        obs = EmailObservable(
            sender_address="spoof@unconfigured.com",
            recipient_address="victim@target.com",
            subject="Phishing Campaign",
        )

        findings = analyzer.analyze(obs)

        titles = [f.title for f in findings]
        assert any("Missing SPF Record" in t for t in titles)
        assert any("Missing DMARC Policy Record" in t for t in titles)
