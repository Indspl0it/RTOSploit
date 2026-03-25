"""Scan runner — look up, configure, and run a scanner module's assessment pipeline."""

from __future__ import annotations

import logging
from typing import Optional

from rtosploit.scanners.base import ScanResult
from rtosploit.scanners.registry import get_registry
from rtosploit.scanners.runtime_bridge import ScanInjector, GDBInterface
from rtosploit.scanners.target import ScanTarget

logger = logging.getLogger(__name__)


def run_scan(
    module_path: str,
    options: dict,
    payload: Optional[bytes] = None,
    timeout: int = 300,
    inject: Optional[GDBInterface] = None,
    inject_address: Optional[int] = None,
    trigger_address: Optional[int] = None,
) -> ScanResult:
    """Look up, configure, and run a scanner module's vulnerability assessment.

    Args:
        module_path: e.g. "freertos/heap_overflow"
        options: dict of option_name -> value
        payload: raw payload bytes (if any)
        timeout: seconds before aborting
        inject: optional GDBInterface for live payload injection.
            When provided, a successful scan result is automatically
            injected into firmware memory via :class:`ScanInjector`.
        inject_address: target memory address for injection (required
            when *inject* is set).
        trigger_address: optional breakpoint address to observe exploit
            landing after injection.

    Returns:
        ScanResult (with injection notes appended when *inject* is used)
    """
    registry = get_registry()
    module_class = registry.get(module_path)
    if module_class is None:
        available = [p for p, *_ in registry.list_all()]
        raise ValueError(
            f"Module not found: {module_path}. Available: {available}"
        )

    module = module_class()
    for name, value in options.items():
        module.set_option(name, value)
    module.validate()

    target = ScanTarget.from_firmware_path(
        firmware_path=module.get_option("firmware"),
        machine_name=module.get_option("machine"),
        start_qemu=module.requirements().get("qemu", False),
    )

    try:
        with target:
            # Pre-check
            if not module.check(target):
                return ScanResult(
                    module=module_path,
                    status="not_vulnerable",
                    target_rtos=target.rtos_type,
                    architecture=target.architecture,
                    technique=module.category,
                    notes=["check() returned False — target does not appear vulnerable"],
                    cve=getattr(module, "cve", None),
                )

            # Execute
            result = module.exploit(target, payload)

            # Optionally inject into live firmware via GDB
            if inject is not None and result.status == "success":
                injector = ScanInjector(inject)
                if trigger_address:
                    inj_result = injector.inject_and_trigger(
                        result,
                        payload=payload,
                        target_address=inject_address,
                        trigger_address=trigger_address,
                    )
                else:
                    inj_result = injector.inject_payload(
                        result,
                        payload=payload,
                        target_address=inject_address,
                    )
                result.notes.append(f"injection: {inj_result.detail or 'ok'}")
                if inj_result.payload_written:
                    result.notes.append(
                        f"injected {inj_result.payload_size} bytes "
                        f"at 0x{inj_result.payload_address:08X}"
                    )

            return result
    except Exception as e:
        logger.error(f"Scan error: {e}")
        return ScanResult(
            module=module_path,
            status="error",
            target_rtos="unknown",
            architecture="unknown",
            technique=module.category if module else "unknown",
            notes=[str(e)],
        )
    finally:
        try:
            module.cleanup(target)
        except Exception:
            pass
