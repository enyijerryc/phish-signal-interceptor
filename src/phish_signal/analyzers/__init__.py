"""Analyzers package for phish-signal-interceptor.

Contains modular, pluggable detection analyzers:
    - DNSPostureAnalyzer: MX, SPF, and DMARC spoofing configuration audits
"""

from phish_signal.analyzers.dns_posture import (
    DNSPostureAnalyzer,
    extract_domain,
    parse_dmarc_policy,
    parse_spf_qualifier,
)

__all__ = [
    "DNSPostureAnalyzer",
    "extract_domain",
    "parse_dmarc_policy",
    "parse_spf_qualifier",
]
