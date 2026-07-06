"""Core data models for the Bluetooth security assessment CLI tool."""

from dataclasses import dataclass, field


@dataclass(frozen=False)
class BtDevice:
    """A discovered device, progressively enriched after construction.

    Explicitly mutable (frozen=False, the dataclass default, stated here to
    make the intent obvious): scan/fingerprint.py builds one from raw
    advertisement data, then fingerprint_device() fills in airoha_soc and
    matched_profile afterwards once catalog matching has run. There's no
    single call site that has every field up front.
    """

    address: str
    name: str | None
    rssi: int | None
    transport: str
    manufacturer_data: dict[int, bytes] = field(default_factory=dict)
    airoha_soc: str | None = None
    matched_profile: dict | None = None


@dataclass(frozen=False)
class RuleFlag:
    """A single finding raised by a probe or drift/impersonation check.

    cve is None for heuristic findings that aren't tied to a specific
    numbered vulnerability - the Phase 6/7 drift and impersonation flags
    (IDENTITY_DRIFT, GATT_TABLE_DRIFT, FIRMWARE_DOWNGRADE, BOND_STATE_DRIFT,
    POSSIBLE_IMPERSONATION) all do this, since they detect compromise
    patterns rather than a specific CVE. New flag types should follow the
    same convention rather than inventing a placeholder CVE id.
    """

    flag_id: str
    severity: str
    description: str
    cve: str | None = None
    evidence: dict = field(default_factory=dict)


@dataclass(frozen=False)
class AssessmentResult:
    device: BtDevice
    verdict: str
    flags: list[RuleFlag] = field(default_factory=list)
