"""CVE correlator — matches firmware fingerprints to known CVEs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from rtosploit.cve.database import CVEDatabase, CVEEntry

_SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass
class CorrelationResult:
    """Result of correlating a firmware fingerprint against the CVE database."""

    rtos: str
    version: Optional[str]
    matching_cves: list[CVEEntry] = field(default_factory=list)
    exploitable_cves: list[CVEEntry] = field(default_factory=list)
    total_cves: int = 0
    highest_severity: str = "info"


class CVECorrelator:
    """Correlates RTOS fingerprints against a CVE database."""

    def __init__(self, database: CVEDatabase) -> None:
        self._db = database

    # RTOS types that wrap another RTOS — also search the underlying RTOS CVEs
    _UNDERLYING_RTOS = {
        "esp-idf": "freertos",
    }

    def correlate(
        self, rtos: str, version: Optional[str] = None
    ) -> CorrelationResult:
        """Look up CVEs for a given RTOS and optional version.

        For RTOS types that wrap another (e.g. ESP-IDF wraps FreeRTOS),
        also includes CVEs from the underlying RTOS.

        Returns a CorrelationResult with matching CVEs, the exploitable
        subset (has_exploit=True), and the highest severity found.
        """
        matching = self._db.lookup(rtos, version)

        # Also search underlying RTOS CVEs (e.g. esp-idf -> freertos)
        underlying = self._UNDERLYING_RTOS.get(rtos.lower())
        if underlying:
            underlying_cves = self._db.lookup(underlying, None)
            seen_ids = {cve.cve_id for cve in matching}
            for cve in underlying_cves:
                if cve.cve_id not in seen_ids:
                    matching.append(cve)
                    seen_ids.add(cve.cve_id)

        exploitable = [cve for cve in matching if cve.has_exploit]

        highest = "info"
        for cve in matching:
            sev = cve.severity.lower()
            if _SEVERITY_ORDER.get(sev, 0) > _SEVERITY_ORDER.get(highest, 0):
                highest = sev

        return CorrelationResult(
            rtos=rtos,
            version=version,
            matching_cves=matching,
            exploitable_cves=exploitable,
            total_cves=len(matching),
            highest_severity=highest,
        )

    def correlate_from_fingerprint(
        self, fingerprint_data: dict
    ) -> CorrelationResult:
        """Correlate from a dict with 'rtos' and 'version' keys.

        Accepts the output of ``fingerprint_firmware()`` converted to dict,
        or any dict with at least a ``rtos`` key.
        """
        rtos = fingerprint_data.get("rtos", fingerprint_data.get("rtos_type", ""))
        version = fingerprint_data.get("version")
        return self.correlate(rtos, version)
