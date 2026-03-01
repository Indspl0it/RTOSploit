"""SARIF 2.1.0 report generator for RTOSploit findings."""

from __future__ import annotations

import json
from typing import Any

from rtosploit import __version__
from rtosploit.reporting.models import EngagementReport, Finding

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)

SEVERITY_MAP: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


class SARIFGenerator:
    """Generate SARIF 2.1.0 reports from an EngagementReport."""

    def generate(self, report: EngagementReport) -> dict[str, Any]:
        """Produce a SARIF 2.1.0 dict from an EngagementReport."""
        rules = self._build_rules(report.findings)
        results = [self._finding_to_result(f) for f in report.findings]

        return {
            "$schema": SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "RTOSploit",
                            "version": __version__,
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

    def generate_json(self, report: EngagementReport) -> str:
        """Return SARIF as a formatted JSON string."""
        return json.dumps(self.generate(report), indent=2)

    def write(self, report: EngagementReport, path: str) -> None:
        """Write SARIF JSON to a file."""
        with open(path, "w") as fh:
            fh.write(self.generate_json(report))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_rules(findings: list[Finding]) -> list[dict[str, Any]]:
        """Build the rules array — one rule per unique dedup_hash."""
        seen: dict[str, dict[str, Any]] = {}
        for f in findings:
            rule_id = f.dedup_hash or f.id
            if rule_id not in seen:
                seen[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": f.title},
                    "defaultConfiguration": {
                        "level": SEVERITY_MAP.get(f.severity, "note"),
                    },
                }
        return list(seen.values())

    @staticmethod
    def _finding_to_result(finding: Finding) -> dict[str, Any]:
        """Convert a single Finding to a SARIF result entry."""
        rule_id = finding.dedup_hash or finding.id

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": SEVERITY_MAP.get(finding.severity, "note"),
            "message": {"text": finding.description},
        }

        # Add logical location for firmware addresses
        logical_locations: list[dict[str, Any]] = []
        if finding.pc is not None:
            logical_locations.append(
                {
                    "name": f"0x{finding.pc:08x}",
                    "kind": "function",
                    "fullyQualifiedName": f"firmware+0x{finding.pc:08x}",
                }
            )
        if finding.fault_address is not None:
            logical_locations.append(
                {
                    "name": f"fault@0x{finding.fault_address:08x}",
                    "kind": "variable",
                    "fullyQualifiedName": f"memory+0x{finding.fault_address:08x}",
                }
            )
        if logical_locations:
            result["locations"] = [
                {"logicalLocations": logical_locations}
            ]

        # Attach properties for extra metadata
        properties: dict[str, Any] = {}
        if finding.crash_type:
            properties["crashType"] = finding.crash_type
        if finding.cve:
            properties["cve"] = finding.cve
        if finding.exploit_module:
            properties["exploitModule"] = finding.exploit_module
        if finding.registers:
            properties["registers"] = {
                k: f"0x{v:08x}" for k, v in finding.registers.items()
            }
        if finding.stack_trace:
            properties["stackTrace"] = [
                f"0x{addr:08x}" for addr in finding.stack_trace
            ]
        if properties:
            result["properties"] = properties

        return result
