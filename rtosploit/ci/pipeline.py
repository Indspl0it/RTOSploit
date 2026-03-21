"""CI/CD pipeline — thin orchestrator that ties all RTOSploit phases together."""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class CIConfig:
    """Configuration for a CI/CD pipeline run."""

    firmware_path: str
    machine: str = "mps2-an385"
    fuzz_timeout: int = 60
    output_dir: str = "scan-output"
    formats: list[str] = field(default_factory=lambda: ["sarif", "html"])
    fail_on: str = "critical"  # critical|high|medium|low|any
    skip_fuzz: bool = False
    skip_cve: bool = False
    minimize: bool = True
    architecture: str = "armv7m"


class CIPipeline:
    """Orchestrates the full RTOSploit security scan pipeline.

    Ties together firmware loading, fingerprinting, CVE correlation,
    fuzzing, crash triage, and report generation into a single run.
    """

    def __init__(self, config: CIConfig) -> None:
        self.config = config
        self.findings: list = []
        self.coverage_stats: Optional[dict] = None
        self.metadata: dict[str, Any] = {}

    def run(self) -> int:
        """Run the full CI pipeline.

        Returns
        -------
        int
            Exit code: 0 = clean, 1 = findings exceed threshold, 2 = error.
        """
        try:
            start_time = time.time()

            # Step 1: Load firmware
            self._load_firmware()

            # Step 2: Fingerprint
            fingerprint = self._fingerprint()

            # Step 3: CVE correlation (if not skipped)
            if not self.config.skip_cve:
                self._correlate_cves(fingerprint)

            # Step 4: Fuzz (if not skipped)
            crash_dir = None
            if not self.config.skip_fuzz:
                crash_dir = self._fuzz()

            # Step 5: Triage crashes
            if crash_dir:
                self._triage(crash_dir)

            # Step 6: Build report
            report = self._build_report(fingerprint)

            # Step 7: Generate outputs
            self._generate_outputs(report)

            elapsed = time.time() - start_time
            self.metadata["elapsed_seconds"] = round(elapsed, 1)

            # Step 8: Determine exit code
            return self._determine_exit_code()

        except Exception as e:
            logger.error(f"Pipeline error: {e}")
            return 2

    # ------------------------------------------------------------------
    # Pipeline steps
    # ------------------------------------------------------------------

    def _load_firmware(self) -> None:
        """Load the firmware image and store info in metadata."""
        from rtosploit.utils.binary import load_firmware

        fw = load_firmware(self.config.firmware_path)
        self.metadata["firmware_path"] = self.config.firmware_path
        self.metadata["firmware_format"] = fw.format.name
        self.metadata["firmware_size"] = len(fw.data)
        self.metadata["base_address"] = fw.base_address
        self.metadata["entry_point"] = fw.entry_point
        self._firmware = fw

    def _fingerprint(self) -> dict:
        """Fingerprint the loaded firmware for RTOS detection.

        Returns a dict with rtos, version, confidence keys.
        If fingerprinting fails, returns an empty dict so the pipeline continues.
        """
        try:
            from rtosploit.analysis.fingerprint import fingerprint_firmware

            fp = fingerprint_firmware(self._firmware)
            result = {
                "rtos": fp.rtos_type,
                "version": fp.version,
                "confidence": fp.confidence,
                "evidence": fp.evidence,
            }
            self.metadata["fingerprint"] = result
            logger.info(
                "Fingerprint: %s %s (confidence %.0f%%)",
                fp.rtos_type,
                fp.version or "unknown",
                fp.confidence * 100,
            )
            return result
        except Exception as e:
            logger.warning("Fingerprinting failed: %s", e)
            return {}

    def _correlate_cves(self, fingerprint: dict) -> None:
        """Correlate firmware fingerprint against the CVE database."""
        from rtosploit.cve.database import CVEDatabase
        from rtosploit.cve.correlator import CVECorrelator
        from rtosploit.reporting.models import finding_from_cve

        rtos = fingerprint.get("rtos", "")
        if not rtos or rtos == "unknown":
            logger.info("No RTOS identified — skipping CVE correlation")
            return

        db = CVEDatabase()
        db.load()
        correlator = CVECorrelator(db)
        result = correlator.correlate_from_fingerprint(fingerprint)

        logger.info(
            "CVE correlation: %d matching CVEs (highest severity: %s)",
            result.total_cves,
            result.highest_severity,
        )

        version = fingerprint.get("version", "")
        for cve_entry in result.matching_cves:
            finding = finding_from_cve(cve_entry, rtos=rtos, version=version or "")
            self.findings.append(finding)

        self.metadata["cve_total"] = result.total_cves
        self.metadata["cve_highest_severity"] = result.highest_severity

    def _fuzz(self) -> Optional[str]:
        """Run the fuzz engine or check for pre-existing crash files.

        If fuzz_timeout > 0, runs the QEMU-based fuzz engine. Also checks
        for pre-existing crash files as a fallback.

        Returns the crash directory path if crashes are found, else None.
        """
        output_dir = Path(self.config.output_dir)
        crashes_dir = output_dir / "crashes"
        corpus_dir = output_dir / "corpus"

        # Check for pre-existing crash files first
        if crashes_dir.is_dir():
            json_files = list(crashes_dir.glob("*.json"))
            if json_files:
                logger.info(
                    "Found %d pre-existing crash files in %s", len(json_files), crashes_dir
                )
                self.metadata["crash_files_found"] = len(json_files)
                return str(crashes_dir)

        # Run the fuzzer if timeout > 0
        if self.config.fuzz_timeout > 0:
            os.makedirs(crashes_dir, exist_ok=True)
            os.makedirs(corpus_dir, exist_ok=True)

            from rtosploit.fuzzing import FuzzEngine

            engine = FuzzEngine(
                firmware_path=self.config.firmware_path,
                machine_name=self.config.machine,
                inject_addr=0x20010000,
                inject_size=256,
                exec_timeout=0.05,
                jobs=1,
            )

            final = engine.run(
                timeout=self.config.fuzz_timeout,
                corpus_dir=str(corpus_dir),
                crash_dir=str(crashes_dir),
            )

            self.metadata["fuzz_executions"] = final.executions
            self.metadata["fuzz_coverage"] = final.coverage

            # Check for crashes after fuzzing
            if crashes_dir.is_dir():
                json_files = list(crashes_dir.glob("*.json"))
                if json_files:
                    logger.info(
                        "Fuzzer produced %d crash files", len(json_files)
                    )
                    self.metadata["crash_files_found"] = len(json_files)
                    return str(crashes_dir)

            logger.info("Fuzzer completed — no crashes found")
            return None

        logger.info("Fuzzing skipped (fuzz_timeout=0)")
        return None

    def _triage(self, crash_dir: str) -> None:
        """Triage crashes and convert to findings."""
        from rtosploit.triage.pipeline import TriagePipeline
        from rtosploit.reporting.models import finding_from_triaged_crash

        pipeline = TriagePipeline(
            firmware_path=self.config.firmware_path,
            machine=self.config.machine,
            minimize=self.config.minimize,
        )
        triaged_crashes = pipeline.run(crash_dir)

        for tc in triaged_crashes:
            finding = finding_from_triaged_crash(tc)
            self.findings.append(finding)

        self.metadata["triaged_crashes"] = len(triaged_crashes)
        logger.info("Triaged %d crashes", len(triaged_crashes))

    def _build_report(self, fingerprint: dict) -> "EngagementReport":  # noqa: F821
        """Build an EngagementReport from accumulated findings."""
        from rtosploit.reporting.models import EngagementReport

        return EngagementReport(
            engagement_id=f"ci-scan-{int(time.time())}",
            timestamp=int(time.time()),
            target_firmware=self.config.firmware_path,
            target_rtos=fingerprint.get("rtos"),
            target_version=fingerprint.get("version"),
            target_architecture=self.config.architecture,
            findings=self.findings,
            coverage_stats=self.coverage_stats,
            metadata=self.metadata,
        )

    def _generate_outputs(self, report: "EngagementReport") -> None:  # noqa: F821
        """Generate SARIF and/or HTML reports based on config."""
        output_path = Path(self.config.output_dir)
        os.makedirs(output_path, exist_ok=True)

        files_written: list[str] = []

        if "sarif" in self.config.formats:
            from rtosploit.reporting.sarif import SARIFGenerator

            sarif_path = str(output_path / "report.sarif.json")
            SARIFGenerator().write(report, sarif_path)
            files_written.append(sarif_path)
            logger.info("SARIF report written to %s", sarif_path)

        if "html" in self.config.formats:
            from rtosploit.reporting.html import HTMLGenerator

            html_path = str(output_path / "report.html")
            HTMLGenerator().write(report, html_path)
            files_written.append(html_path)
            logger.info("HTML report written to %s", html_path)

        self.metadata["output_files"] = files_written

    def _determine_exit_code(self) -> int:
        """Check findings against the fail_on threshold.

        Returns 0 if no findings exceed the threshold, 1 otherwise.
        """
        severity_order = ["info", "low", "medium", "high", "critical"]

        if self.config.fail_on == "any" and self.findings:
            return 1

        if self.config.fail_on in severity_order:
            threshold_idx = severity_order.index(self.config.fail_on)
        else:
            threshold_idx = 4  # default to critical

        for finding in self.findings:
            sev = finding.severity.lower() if hasattr(finding, "severity") else "info"
            finding_idx = (
                severity_order.index(sev) if sev in severity_order else 0
            )
            if finding_idx >= threshold_idx:
                return 1

        return 0
