"""
Header & Payload/URL Analyzer for phish-signal-interceptor.

This analyzer examines the email's internal transport headers and body URLs
to detect identity spoofing and malicious payload links.

Key Detection Rules:
    1. Header Misalignment: RFC 5322 'From:' domain differs from the
       RFC 5321 'Return-Path' envelope domain (spoofing indicator).
    2. Display Name Deception: Human display name contains brand keywords
       (e.g., 'PayPal', 'Chase', 'Microsoft', 'Security') while the sender
       domain belongs to an unrelated third party.
    3. Naked IP URLs: Hyperlinks in the email body pointing to raw IP addresses
       (e.g., 'http://192.168.1.1/login') used to evade domain reputation filters.

References:
    - RFC 5322: Internet Message Format (From, Subject, Date)
    - RFC 5321: Simple Mail Transfer Protocol (Return-Path / MAIL FROM)
    - MITRE ATT&CK T1566.001: Spearphishing Attachment
    - MITRE ATT&CK T1566.002: Spearphishing Link
"""

import ipaddress
import re
from urllib.parse import urlparse

from phish_signal.analyzers.dns_posture import extract_domain
from phish_signal.schemas.finding import DetectionFinding, Severity
from phish_signal.schemas.observable import EmailObservable

# Common high-value targets frequently spoofed in phishing campaigns
SUSPICIOUS_BRAND_KEYWORDS = [
    "paypal",
    "chase",
    "bank of america",
    "wells fargo",
    "microsoft",
    "apple",
    "google",
    "amazon",
    "netflix",
    "secure",
    "security team",
    "account verification",
    "it support",
]


def check_domain_alignment(from_address: str, return_path: str | None) -> bool:
    """Checks if the From domain and Return-Path domain match.

    Returns:
        True if both domains align (or return_path is missing/empty).
        False if both are present but point to different domains.
    """
    if not return_path:
        return True

    try:
        from_domain = extract_domain(from_address)
        return_domain = extract_domain(return_path)
        return from_domain == return_domain
    except ValueError:
        # If either email is unparseable, treat as misaligned
        return False


def is_naked_ip_url(url: str) -> bool:
    """Detects whether a URL host is a raw IPv4 or IPv6 address.

    Examples:
        'http://185.220.101.5/verify' -> True
        'https://accounts.google.com/login' -> False
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False

        # Attempt to parse as an IP address; ValueError means it's a domain name
        ipaddress.ip_address(hostname)
        return True
    except (ValueError, AttributeError):
        return False


def detect_display_name_deception(display_name: str | None, sender_address: str) -> str | None:
    """Checks if display name claims a sensitive brand not found in sender domain.

    Returns:
        The matched brand keyword if deception is suspected, else None.
    """
    if not display_name:
        return None

    name_lower = display_name.lower()
    try:
        sender_domain = extract_domain(sender_address)
    except ValueError:
        sender_domain = ""

    for brand in SUSPICIOUS_BRAND_KEYWORDS:
        if brand in name_lower and brand not in sender_domain:
            return brand

    return None


class HeaderPayloadAnalyzer:
    """Evaluates RFC header alignment, display name deception, and URL patterns."""

    ANALYZER_ID = "header_payload"

    def analyze(self, observable: EmailObservable) -> list[DetectionFinding]:
        """Runs header alignment and payload link heuristics against the observable."""
        findings: list[DetectionFinding] = []

        # 1. Check RFC 5322 From vs RFC 5321 Return-Path alignment
        if observable.return_path:
            is_aligned = check_domain_alignment(observable.sender_address, observable.return_path)
            if not is_aligned:
                try:
                    from_domain = extract_domain(observable.sender_address)
                    return_domain = extract_domain(observable.return_path)
                except ValueError:
                    from_domain = observable.sender_address
                    return_domain = observable.return_path

                findings.append(
                    DetectionFinding(
                        analyzer_id=self.ANALYZER_ID,
                        title="RFC Header Alignment Failure (From vs Return-Path Mismatch)",
                        description=(
                            f"The visible sender address ({from_domain}) does not match "
                            f"the envelope Return-Path domain ({return_domain}). "
                            "This is a classic indicator of sender spoofing or unauthorized relaying."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.85,
                        mitre_technique_id="T1566.002",
                        evidence={
                            "from_address": observable.sender_address,
                            "return_path": observable.return_path,
                            "from_domain": from_domain,
                            "return_domain": return_domain,
                        },
                    )
                )

        # 2. Check Display Name Brand Impersonation
        brand_impersonated = detect_display_name_deception(
            observable.sender_display_name,
            observable.sender_address,
        )
        if brand_impersonated:
            findings.append(
                DetectionFinding(
                    analyzer_id=self.ANALYZER_ID,
                    title=f"Display Name Impersonation Detected ('{brand_impersonated}')",
                    description=(
                        f"Display name '{observable.sender_display_name}' claims to represent "
                        f"'{brand_impersonated}', but the actual sending domain is "
                        f"'{extract_domain(observable.sender_address)}'."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.80,
                    mitre_technique_id="T1566.002",
                    evidence={
                        "display_name": str(observable.sender_display_name),
                        "sender_address": observable.sender_address,
                        "brand_detected": brand_impersonated,
                    },
                )
            )

        # 3. Check for Naked IP URLs in email body
        for url in observable.urls_extracted:
            if is_naked_ip_url(url):
                findings.append(
                    DetectionFinding(
                        analyzer_id=self.ANALYZER_ID,
                        title="Suspicious Naked IP Hyperlink in Body",
                        description=(
                            f"The email body contains a hyperlink '{url}' pointing directly to a raw IP address "
                            "instead of a registered domain. Attackers use this to evade DNS reputation checks."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=0.95,
                        mitre_technique_id="T1566.002",
                        evidence={"malicious_url": url},
                    )
                )

        return findings
