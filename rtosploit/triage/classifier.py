"""Exploitability classifier for Cortex-M crash data (MSEC-style heuristics)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from rtosploit.instrumentation.events import classify_cfsr


class Exploitability(Enum):
    EXPLOITABLE = "exploitable"
    PROBABLY_EXPLOITABLE = "probably_exploitable"
    PROBABLY_NOT = "probably_not_exploitable"
    UNKNOWN = "unknown"


@dataclass
class TriageResult:
    """Result of crash exploitability classification."""

    exploitability: Exploitability
    reasons: list[str] = field(default_factory=list)
    cfsr_flags: list[str] = field(default_factory=list)
    fault_type: str = "unknown"
    write_target: Optional[int] = None
    pc_control: bool = False
    sp_control: bool = False


# Normal Cortex-M flash code region (STM32 typical)
_CODE_RANGE_START = 0x08000000
_CODE_RANGE_END = 0x08FFFFFF

# Typical SRAM stack range for Cortex-M
_STACK_RANGE_START = 0x20000000
_STACK_RANGE_END = 0x2007FFFF


class ExploitabilityClassifier:
    """Classify crash exploitability using CFSR bits and crash metadata.

    Modelled after Microsoft !exploitable (MSEC) heuristics adapted for
    ARM Cortex-M fault registers.
    """

    def classify(self, crash_data: dict) -> TriageResult:
        """Classify a crash dict and return a TriageResult.

        Expected crash_data keys:
            crash_type (str), cfsr (int), pc (int), fault_address (int),
            registers (dict), stack_trace (list), pre_crash_events (list[str])
        """
        crash_type = crash_data.get("crash_type", "unknown")
        cfsr = crash_data.get("cfsr", 0)
        pc = crash_data.get("pc", 0)
        fault_address = crash_data.get("fault_address", 0)
        registers = crash_data.get("registers", {})

        cfsr_flags = classify_cfsr(cfsr) if cfsr else []

        result = TriageResult(
            exploitability=Exploitability.UNKNOWN,
            cfsr_flags=cfsr_flags,
            fault_type=crash_type,
        )

        # Detect PC control: PC outside normal code region
        if pc and not (_CODE_RANGE_START <= pc <= _CODE_RANGE_END):
            result.pc_control = True

        # Detect SP control: SP outside normal stack region
        sp = registers.get("sp", registers.get("r13", 0))
        if sp and not (_STACK_RANGE_START <= sp <= _STACK_RANGE_END):
            result.sp_control = True

        # --- Classification rules (highest severity first) ---

        # EXPLOITABLE: PC in non-executable region (instruction access violations)
        if "IACCVIOL" in cfsr_flags:
            result.exploitability = Exploitability.EXPLOITABLE
            result.reasons.append(
                "Instruction access violation (IACCVIOL): "
                "PC points to non-executable region"
            )
            return result

        if "IBUSERR" in cfsr_flags:
            result.exploitability = Exploitability.EXPLOITABLE
            result.reasons.append(
                "Instruction bus error (IBUSERR): "
                "PC points to invalid memory region"
            )
            return result

        # EXPLOITABLE: Stack canary violation
        if crash_type == "StackCanaryViolation":
            result.exploitability = Exploitability.EXPLOITABLE
            result.reasons.append(
                "Stack canary violation detected: "
                "attacker-controlled stack write"
            )
            return result

        # EXPLOITABLE: Heap metadata corruption
        if crash_type == "HeapMetadataCorruption":
            result.exploitability = Exploitability.EXPLOITABLE
            result.reasons.append(
                "Heap metadata corruption: "
                "potential arbitrary write via heap exploitation"
            )
            return result

        # EXPLOITABLE: PC control detected (regardless of CFSR)
        if result.pc_control:
            result.exploitability = Exploitability.EXPLOITABLE
            result.reasons.append(
                f"PC control detected: PC=0x{pc:08x} outside code region "
                f"[0x{_CODE_RANGE_START:08x}-0x{_CODE_RANGE_END:08x}]"
            )
            return result

        # PROBABLY_EXPLOITABLE: Data access violation with precise error
        if "DACCVIOL" in cfsr_flags or "PRECISERR" in cfsr_flags:
            result.exploitability = Exploitability.PROBABLY_EXPLOITABLE
            reasons = []
            if "DACCVIOL" in cfsr_flags:
                reasons.append("Data access violation (DACCVIOL)")
            if "PRECISERR" in cfsr_flags:
                reasons.append("Precise bus error (PRECISERR)")
            result.reasons.append(
                f"{' + '.join(reasons)}: "
                f"potential heap metadata write at 0x{fault_address:08x}"
            )
            if fault_address:
                result.write_target = fault_address
            return result

        # PROBABLY_EXPLOITABLE: Stack error during exception entry
        if "MSTKERR" in cfsr_flags:
            result.exploitability = Exploitability.PROBABLY_EXPLOITABLE
            result.reasons.append(
                "MemManage stacking error (MSTKERR): "
                "write to corrupted stack pointer during exception entry"
            )
            return result

        # PROBABLY_NOT: Undefined instruction
        if "UNDEFINSTR" in cfsr_flags:
            result.exploitability = Exploitability.PROBABLY_NOT
            result.reasons.append(
                "Undefined instruction (UNDEFINSTR): "
                "likely code corruption or misaligned branch, "
                "low exploitability without further control"
            )
            return result

        # PROBABLY_NOT: Division by zero
        if "DIVBYZERO" in cfsr_flags:
            result.exploitability = Exploitability.PROBABLY_NOT
            result.reasons.append(
                "Division by zero (DIVBYZERO): "
                "arithmetic error, typically not exploitable"
            )
            return result

        # UNKNOWN: no matching pattern
        result.exploitability = Exploitability.UNKNOWN
        result.reasons.append(
            f"Unknown fault pattern: crash_type={crash_type}, "
            f"cfsr_flags={cfsr_flags}"
        )
        return result
