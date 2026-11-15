"""Tests for the RFC Header & Payload/URL Analyzer (Milestone 3).

These tests verify:
    1. check_domain_alignment catches mismatches between From and Return-Path.
    2. is_naked_ip_url detects raw IPv4 and IPv6 URLs in the email body.
    3. detect_display_name_deception catches brand impersonation.
    4. HeaderPayloadAnalyzer integration tests (spoofed email vs clean email).
"""

import pytest

from phish_signal.analyzers.header_analyzer import (
    HeaderPayloadAnalyzer,
    check_domain_alignment,
    detect_display_name_deception,
    is_naked_ip_url,
)
from phish_signal.schemas.finding import Severity
from phish_signal.schemas.observable import EmailObservable


# ─── Helper Tests ────────────────────────────────────────────────────


class TestHeaderHelpers:
    """Tests for header and URL validation helpers."""

    def test_domain_alignment_matching(self):
        assert check_domain_alignment("support@paypal.com", "bounce@paypal.com") is True

    def test_domain_alignment_mismatched(self):
        assert check_domain_alignment("support@chase.com", "bounce@evil-tracker.xyz") is False

    def test_domain_alignment_missing_return_path_defaults_true(self):
        assert check_domain_alignment("support@chase.com", None) is True

    def test_naked_ip_url_ipv4(self):
        assert is_naked_ip_url("http://185.220.101.5/login") is True
        assert is_naked_ip_url("https://192.168.1.1:8080/reset") is True

    def test_naked_ip_url_standard_domain(self):
        assert is_naked_ip_url("https://chase.com/login") is False
        assert is_naked_ip_url("http://subdomain.example.org/verify") is False

    def test_naked_ip_invalid_url(self):
        assert is_naked_ip_url("not-a-valid-url") is False

    def test_display_name_deception_detected(self):
        brand = detect_display_name_deception(
            display_name="PayPal Account Security",
            sender_address="attacker@evil-domain.com",
        )
        assert brand == "paypal"

    def test_display_name_legitimate_sender_ignored(self):
        brand = detect_display_name_deception(
            display_name="PayPal Customer Service",
            sender_address="service@paypal.com",
        )
        assert brand is None

    def test_display_name_benign_name_ignored(self):
        brand = detect_display_name_deception(
            display_name="Jeremiah Enyi",
            sender_address="jeremiah@student.edu.ng",
        )
        assert brand is None


# ─── Integration Tests: HeaderPayloadAnalyzer ────────────────────────


class TestHeaderPayloadAnalyzer:
    """Tests for the complete Header and Payload analyzer."""

    def test_spoofed_phishing_email_triggers_all_heuristics(self):
        """A sophisticated phishing email with misaligned headers, display name spoofing, and an IP link."""
        analyzer = HeaderPayloadAnalyzer()

        obs = EmailObservable(
            sender_address="alerts@evil-mailer.net",
            sender_display_name="Chase Fraud Department",
            return_path="bounces@another-spoofer.xyz",
            recipient_address="victim@target.com",
            subject="Urgent: Unauthorized Login Detected",
            urls_extracted=[
                "http://198.51.100.44/chase/login.php",
                "https://legit-looking.com/faq",
            ],
        )

        findings = analyzer.analyze(obs)

        # Should generate 3 distinct findings
        assert len(findings) == 3

        titles = [f.title for f in findings]
        assert any("RFC Header Alignment Failure" in t for t in titles)
        assert any("Display Name Impersonation Detected" in t for t in titles)
        assert any("Suspicious Naked IP Hyperlink" in t for t in titles)

        # The IP URL finding should be critical severity
        ip_finding = next(f for f in findings if "Naked IP" in f.title)
        assert ip_finding.severity == Severity.CRITICAL
        assert ip_finding.confidence == 0.95
        assert ip_finding.mitre_technique_id == "T1566.002"

    def test_clean_corporate_email_triggers_zero_findings(self):
        """A legitimate email from Chase with matching headers and clean URLs."""
        analyzer = HeaderPayloadAnalyzer()

        obs = EmailObservable(
            sender_address="support@chase.com",
            sender_display_name="Chase Support",
            return_path="replies@chase.com",
            recipient_address="customer@target.com",
            subject="Your Monthly Statement",
            urls_extracted=["https://www.chase.com/statements/view"],
        )

        findings = analyzer.analyze(obs)
        assert len(findings) == 0
