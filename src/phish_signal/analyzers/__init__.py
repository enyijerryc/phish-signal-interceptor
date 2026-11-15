"""Analyzers package for phish-signal-interceptor.

Contains modular, pluggable detection analyzers:
    - DNSPostureAnalyzer: MX, SPF, and DMARC spoofing configuration audits
    - HeaderPayloadAnalyzer: RFC 5322/5321 header alignment, display name spoofing, and IP URLs
"""

from phish_signal.analyzers.dns_posture import (
    DNSPostureAnalyzer,
    extract_domain,
    parse_dmarc_policy,
    parse_spf_qualifier,
)
from phish_signal.analyzers.header_analyzer import (
    HeaderPayloadAnalyzer,
    check_domain_alignment,
    detect_display_name_deception,
    is_naked_ip_url,
)

__all__ = [
    "DNSPostureAnalyzer",
    "HeaderPayloadAnalyzer",
    "check_domain_alignment",
    "detect_display_name_deception",
    "extract_domain",
    "is_naked_ip_url",
    "parse_dmarc_policy",
    "parse_spf_qualifier",
]
