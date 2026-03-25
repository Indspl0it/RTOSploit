"""Exploitability classifier for Cortex-M crash data (MSEC-style heuristics).

Supports both QEMU crashes (with CFSR register) and Unicorn/PIP crashes
(with StopReason but no CFSR).
"""

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

# StopReason values from the PIP/Unicorn fuzzing engine that indicate crashes
_STOP_REASON_CRASH = frozenset({
    "unmapped_access",
    "permission_error",
    "stack_overflow",
})

# StopReason values that are clean termination (not crashes)
_STOP_REASON_CLEAN = frozenset({
    "input_exhausted",
    "infinite_loop",
    "timeout",
})


class ExploitabilityClassifier:
    """Classify crash exploitability using CFSR bits, crash metadata, and StopReason.

    Modelled after Microsoft !exploitable (MSEC) heuristics adapted for
    ARM Cortex-M fault registers. Also handles Unicorn-engine crashes
    that have StopReason but no CFSR register.
    """

    def classify(self, crash_data: dict) -> TriageResult:
        """Classify a crash dict and return a TriageResult.

        Expected crash_data keys:
            crash_type (str), cfsr (int), pc (int), fault_address (int),
            registers (dict), stack_trace (list), pre_crash_events (list[str])

        Also supports:
            stop_reason (str): From PIP/Unicorn engine StopReason enum.
            engine_type (str): "qemu" or "unicorn".
        """
        crash_type = crash_data.get("crash_type", "unknown")
        cfsr = crash_data.get("cfsr", 0)
        pc = crash_data.get("pc", 0)
        fault_address = crash_data.get("fault_address", 0)
        registers = crash_data.get("registers", {})
        stop_reason = crash_data.get("stop_reason", "")

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

        # --- If we have CFSR data, use the precise CFSR-based classification ---
        if cfsr_flags:
            return self._classify_cfsr(result, cfsr_flags, pc, fault_address)

        # --- StopReason-based classification (Unicorn/PIP engine, no CFSR) ---
        if stop_reason:
            return self._classify_stop_reason(
                result, stop_reason, crash_type, pc, fault_address
            )

        # --- Fallback: classify by crash_type alone ---
        return self._classify_crash_type(result, crash_type, pc, fault_address)

    # ------------------------------------------------------------------
    # CFSR-based classification (QEMU with real fault registers)
    # ------------------------------------------------------------------

    def _classify_cfsr(
        self, result: TriageResult, cfsr_flags: list[str],
        pc: int, fault_address: int,
    ) -> TriageResult:
        """Classify using CFSR register bits (QEMU path)."""

        # EXPLOITABLE: PC in non-executable region
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

        # Unrecognized CFSR flags
        result.exploitability = Exploitability.UNKNOWN
        result.reasons.append(
            f"Unrecognized CFSR flags: {cfsr_flags}"
        )
        return result

    # ------------------------------------------------------------------
    # StopReason-based classification (Unicorn/PIP engine)
    # ------------------------------------------------------------------

    def _classify_stop_reason(
        self, result: TriageResult, stop_reason: str,
        crash_type: str, pc: int, fault_address: int,
    ) -> TriageResult:
        """Classify using StopReason from the PIP/Unicorn engine."""

        # Clean termination is not a crash
        if stop_reason in _STOP_REASON_CLEAN:
            result.exploitability = Exploitability.PROBABLY_NOT
            result.reasons.append(
                f"Clean termination: {stop_reason}"
            )
            return result

        # Stack overflow: EXPLOITABLE (same as StackCanaryViolation)
        if stop_reason == "stack_overflow":
            result.exploitability = Exploitability.EXPLOITABLE
            result.reasons.append(
                "Stack overflow detected by Unicorn engine: "
                "SP below stack base, potential stack smash"
            )
            return result

        # Permission error: PROBABLY_EXPLOITABLE (write to flash, exec from RAM)
        if stop_reason == "permission_error":
            result.exploitability = Exploitability.PROBABLY_EXPLOITABLE
            result.reasons.append(
                f"Memory permission violation at 0x{fault_address:08x}: "
                "write to read-only region or execute from non-executable region"
            )
            if fault_address:
                result.write_target = fault_address
            return result

        # Unmapped access: severity depends on fault address and PC
        if stop_reason == "unmapped_access":
            # Null or near-null deref: PROBABLY_NOT
            if fault_address < 0x1000:
                result.exploitability = Exploitability.PROBABLY_NOT
                result.reasons.append(
                    f"Null/near-null dereference at 0x{fault_address:08x}: "
                    "likely a null pointer check failure"
                )
                return result

            # PC control: EXPLOITABLE
            if result.pc_control:
                result.exploitability = Exploitability.EXPLOITABLE
                result.reasons.append(
                    f"Unmapped access with PC control: PC=0x{pc:08x} "
                    f"outside code region, fault at 0x{fault_address:08x}"
                )
                return result

            # General unmapped: PROBABLY_EXPLOITABLE
            result.exploitability = Exploitability.PROBABLY_EXPLOITABLE
            result.reasons.append(
                f"Unmapped memory access at 0x{fault_address:08x}: "
                "wild pointer or heap corruption"
            )
            if fault_address:
                result.write_target = fault_address
            return result

        # Unknown stop reason
        result.exploitability = Exploitability.UNKNOWN
        result.reasons.append(
            f"Unknown stop reason: {stop_reason}"
        )
        return result

    # ------------------------------------------------------------------
    # Crash-type-only classification (fallback)
    # ------------------------------------------------------------------

    def _classify_crash_type(
        self, result: TriageResult, crash_type: str,
        pc: int, fault_address: int,
    ) -> TriageResult:
        """Classify using crash_type string alone (no CFSR, no StopReason)."""

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

        # EXPLOITABLE: PC control detected
        if result.pc_control:
            result.exploitability = Exploitability.EXPLOITABLE
            result.reasons.append(
                f"PC control detected: PC=0x{pc:08x} outside code region "
                f"[0x{_CODE_RANGE_START:08x}-0x{_CODE_RANGE_END:08x}]"
            )
            return result

        # UNKNOWN: no matching pattern
        result.exploitability = Exploitability.UNKNOWN
        result.reasons.append(
            f"Unknown fault pattern: crash_type={crash_type}, "
            f"cfsr_flags={result.cfsr_flags}"
        )
        return result
