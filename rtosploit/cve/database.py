"""CVE database for RTOS firmware vulnerabilities."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class CVEEntry:
    """A single CVE record."""

    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    severity: str = "medium"
    affected_product: str = ""  # freertos|threadx|zephyr
    affected_versions: list[str] = field(default_factory=list)  # e.g. ["<=10.4.3"]
    references: list[str] = field(default_factory=list)
    published_date: str = ""
    has_exploit: bool = False  # True if RTOSploit has a module for it

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "affected_product": self.affected_product,
            "affected_versions": self.affected_versions,
            "references": self.references,
            "published_date": self.published_date,
            "has_exploit": self.has_exploit,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CVEEntry":
        return cls(
            cve_id=d["cve_id"],
            description=d.get("description", ""),
            cvss_score=d.get("cvss_score"),
            severity=d.get("severity", "medium"),
            affected_product=d.get("affected_product", ""),
            affected_versions=d.get("affected_versions", []),
            references=d.get("references", []),
            published_date=d.get("published_date", ""),
            has_exploit=d.get("has_exploit", False),
        )


class CVEDatabase:
    """Local CVE database backed by a JSON file.

    Loads from a bundled JSON file by default, or a custom path.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is not None:
            self._db_path = Path(db_path)
        else:
            self._db_path = Path(__file__).parent / "bundled_cves.json"
        self._entries: list[CVEEntry] = []

    def load(self) -> None:
        """Load the JSON database from disk."""
        if not self._db_path.exists():
            self._entries = []
            return
        with open(self._db_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        self._entries = [CVEEntry.from_dict(item) for item in raw]

    def save(self) -> None:
        """Persist entries to the JSON file."""
        with open(self._db_path, "w", encoding="utf-8") as f:
            json.dump([e.to_dict() for e in self._entries], f, indent=2)

    @property
    def entries(self) -> list[CVEEntry]:
        return list(self._entries)

    def lookup(self, product: str, version: Optional[str] = None) -> list[CVEEntry]:
        """Find CVEs matching a product and optionally a version."""
        product_lower = product.lower()
        results = []
        for entry in self._entries:
            if entry.affected_product.lower() != product_lower:
                continue
            if version is not None and entry.affected_versions:
                if not any(
                    self._version_matches(version, constraint)
                    for constraint in entry.affected_versions
                ):
                    continue
            results.append(entry)
        return results

    def search(self, term: str) -> list[CVEEntry]:
        """Free-text search across cve_id, description, and affected_product."""
        term_lower = term.lower()
        results = []
        for entry in self._entries:
            searchable = " ".join([
                entry.cve_id,
                entry.description,
                entry.affected_product,
            ]).lower()
            if term_lower in searchable:
                results.append(entry)
        return results

    def update_from_nvd(self, entries: list[CVEEntry]) -> None:
        """Merge new entries into the database (idempotent by cve_id)."""
        existing_ids = {e.cve_id for e in self._entries}
        for entry in entries:
            if entry.cve_id not in existing_ids:
                self._entries.append(entry)
                existing_ids.add(entry.cve_id)

    @staticmethod
    def _version_matches(version: str, constraint: str) -> bool:
        """Check whether *version* satisfies a version constraint.

        Supported operators: <=, >=, <, >, ==, and bare versions (treated as ==).
        """
        operators = ["<=", ">=", "!=", "==", "<", ">"]
        op = "=="
        constraint_version = constraint
        for candidate_op in operators:
            if constraint.startswith(candidate_op):
                op = candidate_op
                constraint_version = constraint[len(candidate_op):]
                break

        def _parse_version(v: str) -> tuple[int, ...]:
            parts: list[int] = []
            for segment in re.split(r"[.\-]", v.strip()):
                try:
                    parts.append(int(segment))
                except ValueError:
                    break
            return tuple(parts) if parts else (0,)

        v = _parse_version(version)
        c = _parse_version(constraint_version)

        if op == "<=":
            return v <= c
        elif op == ">=":
            return v >= c
        elif op == "<":
            return v < c
        elif op == ">":
            return v > c
        elif op == "!=":
            return v != c
        else:  # ==
            return v == c
