"""Data models for RTOSploit engagement reports."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Finding:
    """A single security finding (crash, exploit/scanner, or CVE match).

    Fields cover all current RTOSploit capabilities:
    - PIP fuzzing crashes (StopReason, blocks_executed, engine_type)
    - QEMU/Unicorn dual-engine results
    - Vulnerability scanner (formerly exploit module) results
    - CVE database matches
    """

    id: str
    title: str
    severity: str  # info | low | medium | high | critical
    category: str  # crash | scanner | exploit | cve
    description: str
    crash_type: Optional[str] = None
    pc: Optional[int] = None
    fault_address: Optional[int] = None
    registers: dict[str, int] = field(default_factory=dict)
    stack_trace: list[int] = field(default_factory=list)
    input_data: Optional[str] = None
    reproducer_path: Optional[str] = None
    dedup_hash: Optional[str] = None
    exploitability: Optional[str] = None
    cfsr_flags: list[str] = field(default_factory=list)
    cve: Optional[str] = None
    exploit_module: Optional[str] = None
    exploit_status: Optional[str] = None
    timestamp: int = 0
    # --- New fields for PIP / Unicorn / dual-engine ---
    stop_reason: Optional[str] = None
    engine_type: Optional[str] = None  # "qemu" | "unicorn"
    blocks_executed: int = 0
    pip_stats: Optional[dict] = None  # PIP handler stats dict


@dataclass
class CoverageStats:
    """Structured coverage statistics for a fuzz campaign."""

    edge_count: int = 0
    total_hits: int = 0
    bitmap_size: int = 65536
    coverage_type: str = "basic"  # "basic" | "fermcov"
    coverage_pct: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_count": self.edge_count,
            "total_hits": self.total_hits,
            "bitmap_size": self.bitmap_size,
            "coverage_type": self.coverage_type,
            "coverage_pct": self.coverage_pct,
        }


@dataclass
class FuzzCampaignStats:
    """Campaign-level fuzzing statistics."""

    executions: int = 0
    crashes: int = 0
    unique_crashes: int = 0
    exec_per_sec: float = 0.0
    elapsed_seconds: float = 0.0
    corpus_size: int = 0
    engine_type: str = "qemu"  # "qemu" | "unicorn"
    coverage: Optional[CoverageStats] = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "executions": self.executions,
            "crashes": self.crashes,
            "unique_crashes": self.unique_crashes,
            "exec_per_sec": round(self.exec_per_sec, 1),
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "corpus_size": self.corpus_size,
            "engine_type": self.engine_type,
        }
        if self.coverage is not None:
            result["coverage"] = self.coverage.to_dict()
        return result


@dataclass
class PeripheralSummary:
    """Summary of peripheral detection results for the report."""

    total_detected: int = 0
    layers_run: list[str] = field(default_factory=list)
    mcu_family: str = "unknown"
    peripherals: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_detected": self.total_detected,
            "layers_run": self.layers_run,
            "mcu_family": self.mcu_family,
            "peripherals": self.peripherals,
        }


@dataclass
class EngagementReport:
    """Top-level engagement report containing all findings and metadata."""

    engagement_id: str
    timestamp: int
    target_firmware: str
    target_rtos: Optional[str] = None
    target_version: Optional[str] = None
    target_architecture: str = "armv7m"
    findings: list[Finding] = field(default_factory=list)
    coverage_stats: Optional[CoverageStats] = None
    fuzz_stats: Optional[FuzzCampaignStats] = None
    peripheral_summary: Optional[PeripheralSummary] = None
    metadata: dict[str, Any] = field(default_factory=dict)


def finding_from_fuzz_report(data: dict) -> Finding:
    """Convert a FuzzReport JSON dict to a Finding.

    Expected fields: crash_type, severity, pc, fault_address, registers,
    stack_trace, input_data, reproducer_path, dedup_hash, id, timestamp.
    Also accepts: stop_reason, engine_type, blocks_executed, pip_stats.
    """
    finding_id = data.get("id") or hashlib.sha256(
        str(data).encode()
    ).hexdigest()[:16]

    crash_type = data.get("crash_type", "unknown")
    severity = data.get("severity", "medium")
    pc = data.get("pc")
    fault_address = data.get("fault_address")
    stop_reason = data.get("stop_reason")
    engine_type = data.get("engine_type")
    blocks_executed = data.get("blocks_executed", 0)
    pip_stats = data.get("pip_stats")

    title = f"Crash: {crash_type}"
    if pc is not None:
        title += f" at PC=0x{pc:08x}"

    description_parts = [f"Crash type: {crash_type}"]
    if stop_reason:
        description_parts.append(f"Stop reason: {stop_reason}")
    if engine_type:
        description_parts.append(f"Engine: {engine_type}")
    if pc is not None:
        description_parts.append(f"Program counter: 0x{pc:08x}")
    if fault_address is not None:
        description_parts.append(f"Fault address: 0x{fault_address:08x}")
    if blocks_executed:
        description_parts.append(f"Blocks executed: {blocks_executed}")
    if data.get("reproducer_path"):
        description_parts.append(f"Reproducer: {data['reproducer_path']}")

    return Finding(
        id=finding_id,
        title=title,
        severity=severity,
        category="crash",
        description="\n".join(description_parts),
        crash_type=crash_type,
        pc=pc,
        fault_address=fault_address,
        registers=data.get("registers", {}),
        stack_trace=data.get("stack_trace", []),
        input_data=data.get("input_data"),
        reproducer_path=data.get("reproducer_path"),
        dedup_hash=data.get("dedup_hash"),
        timestamp=data.get("timestamp", 0),
        stop_reason=stop_reason,
        engine_type=engine_type,
        blocks_executed=blocks_executed,
        pip_stats=pip_stats,
    )


def finding_from_triaged_crash(triaged: "TriagedCrash") -> Finding:  # noqa: F821
    """Convert a TriagedCrash to a Finding.

    Imports TriagedCrash lazily to avoid circular dependencies.
    """
    crash_data = triaged.crash_data
    tr = triaged.triage_result

    crash_type = crash_data.get(
        "fault_type", crash_data.get("crash_type", "unknown")
    )
    pc = crash_data.get("pc", crash_data.get("registers", {}).get("pc", 0))
    fault_address = crash_data.get("fault_address", 0)
    registers = crash_data.get("registers", {})
    stack_trace = crash_data.get("backtrace", [])
    stop_reason = crash_data.get("stop_reason")
    engine_type = crash_data.get("engine_type")
    blocks_executed = crash_data.get("blocks_executed", 0)
    pip_stats = crash_data.get("pip_stats")

    # Map exploitability to severity
    _SEVERITY = {
        "exploitable": "critical",
        "probably_exploitable": "high",
        "probably_not_exploitable": "low",
        "unknown": "medium",
    }
    severity = _SEVERITY.get(tr.exploitability.value, "medium")

    finding_id = triaged.crash_id or hashlib.sha256(
        str(crash_data).encode()
    ).hexdigest()[:16]

    title = f"Crash: {crash_type}"
    if pc:
        title += f" at PC=0x{pc:08x}"
    title += f" [{tr.exploitability.value}]"

    description_parts = [
        f"Crash type: {crash_type}",
        f"Exploitability: {tr.exploitability.value}",
    ]
    if stop_reason:
        description_parts.append(f"Stop reason: {stop_reason}")
    if engine_type:
        description_parts.append(f"Engine: {engine_type}")
    if pc:
        description_parts.append(f"Program counter: 0x{pc:08x}")
    if fault_address:
        description_parts.append(f"Fault address: 0x{fault_address:08x}")
    if blocks_executed:
        description_parts.append(f"Blocks executed: {blocks_executed}")
    if tr.reasons:
        description_parts.append(f"Reasons: {'; '.join(tr.reasons)}")
    if tr.cfsr_flags:
        description_parts.append(f"CFSR flags: {', '.join(tr.cfsr_flags)}")
    if triaged.minimized_input:
        description_parts.append(f"Minimized input: {triaged.minimized_input}")

    return Finding(
        id=finding_id,
        title=title,
        severity=severity,
        category="crash",
        description="\n".join(description_parts),
        crash_type=crash_type,
        pc=pc if pc else None,
        fault_address=fault_address if fault_address else None,
        registers=registers,
        stack_trace=stack_trace,
        input_data=triaged.original_input,
        reproducer_path=triaged.minimized_input or triaged.original_input,
        dedup_hash=None,
        exploitability=tr.exploitability.value,
        cfsr_flags=tr.cfsr_flags,
        timestamp=crash_data.get("timestamp", 0),
        stop_reason=stop_reason,
        engine_type=engine_type,
        blocks_executed=blocks_executed,
        pip_stats=pip_stats,
    )


def finding_from_exploit_result(result_dict: dict) -> Finding:
    """Convert a ScanResult.to_dict() dict to a Finding.

    Expected fields: module, status, target_rtos, cve, technique, notes.
    Works for both legacy exploit modules and renamed scanner modules.
    """
    module = result_dict.get("module", "unknown")
    status = result_dict.get("status", "unknown")
    cve = result_dict.get("cve")
    technique = result_dict.get("technique", "unknown")
    notes = result_dict.get("notes", [])

    finding_id = hashlib.sha256(
        f"{module}:{cve or technique}".encode()
    ).hexdigest()[:16]

    title = f"Scanner: {module}"
    if cve:
        title += f" ({cve})"

    severity = "high" if status == "success" else "medium"
    if cve:
        severity = "critical"

    description_parts = [
        f"Module: {module}",
        f"Status: {status}",
        f"Technique: {technique}",
    ]
    if cve:
        description_parts.append(f"CVE: {cve}")
    if result_dict.get("target_rtos"):
        description_parts.append(f"Target RTOS: {result_dict['target_rtos']}")
    if notes:
        description_parts.append(f"Notes: {'; '.join(notes)}")

    # Use "scanner" category if available; default for results without an
    # explicit category field (e.g. ScanResult.to_dict()).
    category = result_dict.get("category", "scanner")

    return Finding(
        id=finding_id,
        title=title,
        severity=severity,
        category=category,
        description="\n".join(description_parts),
        cve=cve,
        exploit_module=module,
        exploit_status=status,
        timestamp=int(time.time()),
    )


def finding_from_cve(cve_entry: "CVEEntry", rtos: str = "", version: str = "") -> Finding:  # noqa: F821
    """Convert a CVEEntry to a Finding.

    Parameters
    ----------
    cve_entry:
        A ``rtosploit.cve.database.CVEEntry`` instance.
    rtos:
        The target RTOS name (e.g. ``"freertos"``).
    version:
        The detected firmware version string.
    """
    finding_id = hashlib.sha256(
        cve_entry.cve_id.encode()
    ).hexdigest()[:16]

    title = f"CVE: {cve_entry.cve_id}"
    if cve_entry.cvss_score is not None:
        title += f" (CVSS {cve_entry.cvss_score:.1f})"

    description_parts = [cve_entry.description]
    if rtos:
        description_parts.append(f"Affected RTOS: {rtos}")
    if version:
        description_parts.append(f"Detected version: {version}")
    if cve_entry.affected_versions:
        description_parts.append(f"Affected versions: {', '.join(cve_entry.affected_versions)}")
    if cve_entry.references:
        description_parts.append(f"References: {', '.join(cve_entry.references)}")

    return Finding(
        id=finding_id,
        title=title,
        severity=cve_entry.severity,
        category="cve",
        description="\n".join(description_parts),
        cve=cve_entry.cve_id,
        timestamp=int(time.time()),
    )
