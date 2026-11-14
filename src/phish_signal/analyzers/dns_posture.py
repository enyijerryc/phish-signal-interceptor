"""
DNS & Spoofing Posture Analyzer for phish-signal-interceptor.

This analyzer evaluates the sender domain's DNS authentication posture
(MX, SPF, and DMARC records) to detect misconfigurations that allow
attackers to spoof emails without rejection.

Key Detection Rules:
    1. SPF SoftFail (~all) combined with DMARC p=none or missing DMARC
       (The classic vulnerability seen in domains like omniel.com.ng).
    2. Missing SPF record (any sender can forge emails from this domain).
    3. Missing or misaligned DMARC policy (no enforcement on spoofed traffic).
    4. Missing MX records (domain cannot receive mail, often used in spam).

References:
    - RFC 7208: Sender Policy Framework (SPF)
    - RFC 7489: Domain-based Message Authentication, Reporting, and Conformance (DMARC)
    - MITRE ATT&CK T1566.002: Phishing: Spearphishing Link
"""

import dns.resolver
from dns.exception import DNSException

from phish_signal.schemas.finding import DetectionFinding, Severity
from phish_signal.schemas.observable import EmailObservable


def extract_domain(email_address: str) -> str:
    """Extracts and lowercases the domain portion from an email address.

    Args:
        email_address: e.g. 'Security@OMNIEL.COM.NG' or 'test@example.com'

    Returns:
        The lowercase domain, e.g. 'omniel.com.ng'

    Raises:
        ValueError: If '@' is missing or the domain part is empty.
    """
    if "@" not in email_address:
        raise ValueError(f"Invalid email address (missing '@'): {email_address}")

    pieces = email_address.split("@")
    domain = pieces[1].strip().lower()

    if not domain:
        raise ValueError(f"Invalid email address (empty domain): {email_address}")

    return domain


def parse_spf_qualifier(spf_text: str) -> str:
    """Extracts the 'all' qualifier from an SPF TXT record.

    Qualifiers in RFC 7208:
        '-all' -> Fail (HardFail: unauthorized mail must be rejected)
        '~all' -> SoftFail (unauthorized mail accepted but tagged)
        '+all' -> Pass (unauthorized mail explicitly allowed - dangerous)
        '?all' -> Neutral (no policy statement)

    Returns:
        The detected qualifier string (e.g. '~all', '-all'), or 'none'.
    """
    words = spf_text.split()
    for word in words:
        clean = word.strip().lower()
        if clean in ("-all", "~all", "+all", "?all", "all"):
            return clean
    return "none"


def parse_dmarc_policy(dmarc_text: str) -> str:
    """Extracts the 'p=' policy tag from a DMARC TXT record.

    Policies in RFC 7489:
        'p=reject'     -> Maximum enforcement (block spoofed emails)
        'p=quarantine' -> Medium enforcement (send to spam folder)
        'p=none'       -> Zero enforcement (monitor only, deliver to inbox)

    Returns:
        The policy value (e.g. 'reject', 'quarantine', 'none', or 'missing').
    """
    # DMARC tags are separated by semicolons (;)
    tags = dmarc_text.split(";")
    for tag in tags:
        parts = tag.strip().split("=")
        if len(parts) == 2 and parts[0].strip().lower() == "p":
            return parts[1].strip().lower()
    return "missing"


class DNSPostureAnalyzer:
    """Evaluates DNS records (MX, SPF, DMARC) for email spoofing vulnerabilities."""

    ANALYZER_ID = "dns_posture"

    def __init__(self, resolver: dns.resolver.Resolver | None = None):
        """Initializes analyzer with a configurable DNS resolver (allows mocking)."""
        self.resolver = resolver or dns.resolver.Resolver()
        self.resolver.timeout = 3.0
        self.resolver.lifetime = 3.0

    def resolve_txt(self, domain: str) -> list[str]:
        """Queries DNS TXT records for a domain."""
        try:
            answers = self.resolver.resolve(domain, "TXT")
            records = []
            for rdata in answers:
                # TXT records can be split into chunks, join them
                txt_string = "".join([chunk.decode("utf-8") if isinstance(chunk, bytes) else str(chunk) for chunk in rdata.strings])
                records.append(txt_string)
            return records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, DNSException):
            return []

    def resolve_mx(self, domain: str) -> list[str]:
        """Queries DNS MX records for a domain."""
        try:
            answers = self.resolver.resolve(domain, "MX")
            return [str(rdata.exchange).rstrip(".") for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, DNSException):
            return []

    def analyze(self, observable: EmailObservable) -> list[DetectionFinding]:
        """Runs DNS posture checks against the sender's domain.

        Returns a list of DetectionFinding objects if vulnerabilities are found.
        """
        findings: list[DetectionFinding] = []
        domain = extract_domain(observable.sender_address)

        # 1. Check MX records
        mx_records = self.resolve_mx(domain)
        if not mx_records:
            findings.append(
                DetectionFinding(
                    analyzer_id=self.ANALYZER_ID,
                    title="Domain Has No Valid MX Records",
                    description=(
                        f"The domain '{domain}' has no registered Mail Exchange (MX) records. "
                        "Legitimate corporate senders require MX records to receive email replies."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.70,
                    mitre_technique_id="T1566.002",
                    evidence={"domain": domain, "mx_count": "0"},
                )
            )

        # 2. Check SPF record
        txt_records = self.resolve_txt(domain)
        spf_records = [r for r in txt_records if r.startswith("v=spf1")]
        spf_qualifier = "none"
        spf_raw = "none"

        if not spf_records:
            findings.append(
                DetectionFinding(
                    analyzer_id=self.ANALYZER_ID,
                    title="Missing SPF Record (Spoofing Permitted)",
                    description=(
                        f"The domain '{domain}' does not publish an SPF record. "
                        "Any unauthorized mail server on the internet can send emails purporting to be from this domain."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.85,
                    mitre_technique_id="T1566.002",
                    evidence={"domain": domain, "spf_status": "missing"},
                )
            )
        else:
            spf_raw = spf_records[0]
            spf_qualifier = parse_spf_qualifier(spf_raw)

        # 3. Check DMARC record (_dmarc.<domain>)
        dmarc_txt = self.resolve_txt(f"_dmarc.{domain}")
        dmarc_records = [r for r in dmarc_txt if r.startswith("v=DMARC1")]
        dmarc_policy = "missing"
        dmarc_raw = "missing"

        if not dmarc_records:
            findings.append(
                DetectionFinding(
                    analyzer_id=self.ANALYZER_ID,
                    title="Missing DMARC Policy Record",
                    description=(
                        f"The domain '{domain}' has no DMARC record at '_dmarc.{domain}'. "
                        "Receiving mail servers have no instructions on how to treat unauthorized emails."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.75,
                    mitre_technique_id="T1566.002",
                    evidence={"domain": domain, "dmarc_status": "missing"},
                )
            )
        else:
            dmarc_raw = dmarc_records[0]
            dmarc_policy = parse_dmarc_policy(dmarc_raw)

        # 4. The Critical Compound Vulnerability: SPF SoftFail (~all) + DMARC p=none
        # (This is the exact configuration vulnerability of omniel.com.ng)
        if spf_qualifier in ("~all", "?all", "+all") and dmarc_policy in ("none", "missing"):
            findings.append(
                DetectionFinding(
                    analyzer_id=self.ANALYZER_ID,
                    title="Exploitable Spoofing Posture (SPF SoftFail with DMARC p=none)",
                    description=(
                        f"Domain '{domain}' has SPF set to '{spf_qualifier}' but DMARC policy is '{dmarc_policy}'. "
                        "Because neither protocol instructs the receiving server to reject or quarantine unauthorized senders, "
                        "spoofed emails will land directly in the victim's primary inbox."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.90,
                    mitre_technique_id="T1566.002",
                    evidence={
                        "domain": domain,
                        "spf_record": spf_raw,
                        "spf_qualifier": spf_qualifier,
                        "dmarc_policy": dmarc_policy,
                    },
                )
            )

        return findings
