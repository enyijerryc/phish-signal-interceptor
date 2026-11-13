"""
EmailObservable: The validated input schema for phish-signal-interceptor.

This Pydantic model represents all raw, untrusted data extracted from an
email payload (.eml file or manual input) BEFORE any analysis is performed.
Every analyzer receives an immutable EmailObservable instance — they never
modify it, only read from it and produce DetectionFinding outputs.

Design Rationale:
    - Strict type validation catches malformed/missing data at ingestion,
      not inside analyzer logic where debugging is harder.
    - Optional fields (e.g., return_path, message_id) are explicitly typed
      as `str | None` so analyzers can check for missing data and flag it
      as an incomplete observable rather than crashing.
    - This pattern mirrors IntelOwl's observable model where raw indicators
      (IP, domain, hash) are validated before being dispatched to analyzers.

References:
    - RFC 5322 (Internet Message Format): Defines the `From`, `To`,
      `Subject`, `Date`, and `Message-ID` header fields.
    - RFC 5321 (SMTP Protocol): Defines the envelope `MAIL FROM`
      (Return-Path) which can differ from the RFC 5322 `From` header —
      a key spoofing indicator.
"""

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class EmailObservable(BaseModel):
    """Validated representation of an email payload for threat analysis.

    Attributes:
        sender_address: The RFC 5322 'From:' header address (human-facing,
            can be spoofed).
        sender_display_name: The display name portion of the From header
            (e.g., "PayPal Security" in '"PayPal Security" <attacker@evil.com>').
        return_path: The RFC 5321 envelope 'MAIL FROM' / 'Return-Path'
            address. Misalignment with sender_address is a spoofing signal.
        reply_to: The 'Reply-To' header. Attackers often set this to a
            different domain than the From address.
        recipient_address: The 'To:' header address.
        subject: The email subject line.
        message_id: The 'Message-ID' header (globally unique identifier).
        date: The 'Date' header timestamp.
        received_headers: The full chain of 'Received:' headers (ordered
            from most recent to oldest), used for hop analysis.
        body_plain: The plain-text body content (if available).
        body_html: The HTML body content (if available).
        urls_extracted: List of URLs found in the body (both plain and HTML).
        attachments: List of attachment filenames (for future analysis).
        raw_headers: The complete raw header block as a single string,
            preserved for analyzers that need to parse non-standard headers.
    """

    # --- Sender Identity (RFC 5322 + RFC 5321) ---
    sender_address: EmailStr = Field(
        ...,
        description="RFC 5322 'From:' header email address (human-facing, spoofable).",
    )
    sender_display_name: str | None = Field(
        default=None,
        description="Display name from the 'From:' header (e.g., 'PayPal Security').",
    )
    return_path: str | None = Field(
        default=None,
        description="RFC 5321 envelope 'Return-Path' / 'MAIL FROM' address.",
    )
    reply_to: str | None = Field(
        default=None,
        description="'Reply-To' header address (spoofing signal if mismatched).",
    )

    # --- Recipient & Metadata ---
    recipient_address: EmailStr = Field(
        ...,
        description="RFC 5322 'To:' header email address.",
    )
    subject: str = Field(
        ...,
        description="Email subject line.",
    )
    message_id: str | None = Field(
        default=None,
        description="'Message-ID' header (globally unique identifier).",
    )
    date: datetime | None = Field(
        default=None,
        description="'Date' header timestamp.",
    )

    # --- Transport Headers ---
    received_headers: list[str] = Field(
        default_factory=list,
        description="Ordered 'Received:' headers (most recent first) for hop analysis.",
    )

    # --- Body & Payload ---
    body_plain: str | None = Field(
        default=None,
        description="Plain-text body content.",
    )
    body_html: str | None = Field(
        default=None,
        description="HTML body content.",
    )
    urls_extracted: list[str] = Field(
        default_factory=list,
        description="URLs extracted from the email body.",
    )
    attachments: list[str] = Field(
        default_factory=list,
        description="Filenames of email attachments.",
    )

    # --- Raw Preservation ---
    raw_headers: str | None = Field(
        default=None,
        description="Complete raw header block for non-standard header analysis.",
    )

    model_config = {
        "frozen": True,
        "str_strip_whitespace": True,
        "json_schema_extra": {
            "examples": [
                {
                    "sender_address": "security@paypa1.com",
                    "sender_display_name": "PayPal Security Team",
                    "return_path": "bounce@evil-domain.xyz",
                    "reply_to": "reply@evil-domain.xyz",
                    "recipient_address": "victim@example.com",
                    "subject": "Urgent: Your account has been compromised",
                    "message_id": "<fake-id-12345@evil-domain.xyz>",
                    "received_headers": [
                        "from mail.evil-domain.xyz (1.2.3.4) by mx.example.com"
                    ],
                    "body_plain": "Click here to verify your account: http://paypa1-secure.com/login",
                    "urls_extracted": ["http://paypa1-secure.com/login"],
                    "attachments": [],
                }
            ]
        },
    }
