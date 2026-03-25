"""Firmware rehosting engine with peripheral model support.

Orchestrates: QEMU boot -> symbol resolution -> intercept setup -> run loop.
Supports both manual (YAML config) and auto (zero-config detection) modes.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, TYPE_CHECKING

from rtosploit.peripherals.config import PeripheralConfig
from rtosploit.peripherals.dispatcher import InterceptDispatcher
from rtosploit.peripherals.model import PeripheralModel

if TYPE_CHECKING:
    from rtosploit.emulation.qemu import QEMUInstance
    from rtosploit.peripherals.models.mmio_fallback import CompositeMMIOHandler

logger = logging.getLogger(__name__)


def build_unimplemented_device_args(base: int = 0x40000000, size: int = 0x20000000) -> list[str]:
    """Build QEMU args for an unimplemented device covering peripheral space.

    This catches MMIO accesses to unmodeled peripherals, returning 0 instead
    of causing bus faults. Returns empty list if the QEMU version doesn't
    support the 'unimplemented' device.
    """
    qemu = shutil.which("qemu-system-arm")
    if qemu is None:
        return []

    try:
        result = subprocess.run(
            [qemu, "-device", "help"],
            capture_output=True, text=True, timeout=5,
        )
        if "unimplemented" not in result.stdout:
            logger.debug("QEMU does not support 'unimplemented' device, skipping")
            return []
    except Exception:
        return []

    return [
        "-device",
        f"unimplemented,name=peripheral-catch-all,base=0x{base:x},size=0x{size:x}",
    ]


class RehostingEngine:
    """Firmware rehosting engine with peripheral model support.

    Orchestrates: QEMU boot -> symbol resolution -> intercept setup -> run loop.
    """

    def __init__(
        self,
        firmware_path: str,
        machine_name: str,
        peripheral_config: str | None = None,
        config: Any = None,
        auto_mode: bool = False,
    ) -> None:
        self.firmware_path = firmware_path
        self.machine_name = machine_name
        self.peripheral_config_path = peripheral_config
        self._config = config
        self.auto_mode = auto_mode
        self._dispatcher: InterceptDispatcher | None = None
        self._models: dict[str, PeripheralModel] = {}
        self._composite_mmio: CompositeMMIOHandler | None = None
        self._auto_summary: dict[str, Any] = {}

    def setup(self, qemu: QEMUInstance) -> InterceptDispatcher:
        """Set up all intercepts on an already-booted QEMU instance.

        When ``auto_mode`` is True and no ``peripheral_config_path`` is set,
        delegates to :meth:`auto_setup` for zero-config detection.  Otherwise
        uses the manual YAML config path.

        Args:
            qemu: A running QEMUInstance with GDB connected.

        Returns:
            The InterceptDispatcher ready to handle breakpoint events.
        """
        # Delegate to auto_setup when auto_mode is on and no manual config
        if self.auto_mode and self.peripheral_config_path is None:
            return self.auto_setup(qemu)

        gdb = qemu.gdb
        if gdb is None:
            raise RuntimeError("GDB connection required for peripheral intercepts")

        # Load peripheral config
        if self.peripheral_config_path is None:
            raise ValueError("No peripheral config provided")

        fw_path = Path(self.firmware_path)
        if fw_path.suffix in (".elf", ""):
            try:
                pconfig = PeripheralConfig.load_from_elf(
                    self.firmware_path, self.peripheral_config_path
                )
            except Exception:
                logger.warning("ELF symbol resolution failed, loading config without symbols")
                pconfig = PeripheralConfig.load(self.peripheral_config_path)
        else:
            pconfig = PeripheralConfig.load(self.peripheral_config_path)

        # Instantiate models
        self._models = pconfig.instantiate_models()

        # Create dispatcher
        dispatcher = InterceptDispatcher(gdb)

        # Register intercepts
        for intercept in pconfig.get_intercepts():
            if intercept.address is None:
                # Try manual symbol table
                symbols = pconfig.get_symbols()
                for addr, sym_name in symbols.items():
                    if sym_name == intercept.symbol or sym_name == intercept.function:
                        intercept.address = addr
                        break

            if intercept.address is None:
                logger.warning(
                    "Skipping intercept %s — no address resolved",
                    intercept.function,
                )
                continue

            # Find the model instance
            model = self._models.get(intercept.model_class)
            if model is None:
                logger.warning(
                    "Skipping intercept %s — model class %s not instantiated",
                    intercept.function,
                    intercept.model_class,
                )
                continue

            try:
                dispatcher.register(model, intercept.function, intercept.address)
                logger.info(
                    "Registered intercept: %s @ 0x%08x -> %s",
                    intercept.function,
                    intercept.address,
                    model.name,
                )
            except KeyError as e:
                logger.warning("Failed to register %s: %s", intercept.function, e)

        self._dispatcher = dispatcher
        return dispatcher

    def auto_setup(self, qemu: QEMUInstance) -> InterceptDispatcher:
        """Auto-detect peripherals and configure the rehosting engine.

        Performs zero-config peripheral setup by:
        1. Loading and analysing the firmware image
        2. Fingerprinting RTOS, MCU, and architecture
        3. Auto-generating peripheral config (SVD + HAL hooks)
        4. Building a CompositeMMIOHandler for MMIO routing
        5. Registering HAL hook intercepts via the dispatcher

        The method is resilient: individual steps that fail are logged as
        warnings and skipped so partial results are still usable.

        Args:
            qemu: A QEMUInstance (GDB connection required for intercept
                  registration but the config generation works without it).

        Returns:
            The InterceptDispatcher with auto-detected intercepts registered.
        """
        from rtosploit.analysis.fingerprint import fingerprint_firmware
        from rtosploit.peripherals.auto_config import AutoConfigGenerator, resolve_qemu_machine
        from rtosploit.peripherals.models.mmio_fallback import (
            CompositeMMIOHandler,
            CortexMSystemRegisters,
            MMIOFallbackModel,
        )
        from rtosploit.peripherals.models.svd_peripheral import SVDPeripheralModel
        from rtosploit.utils.binary import load_firmware

        gdb = qemu.gdb
        if gdb is None:
            raise RuntimeError("GDB connection required for peripheral intercepts")

        # -- Step (a): Load firmware image -----------------------------------
        try:
            firmware = load_firmware(self.firmware_path)
            logger.info("Loaded firmware: %s (%d bytes)", self.firmware_path, len(firmware.data))
        except Exception as exc:
            logger.error("Failed to load firmware for auto-detection: %s", exc)
            raise

        # -- Step (b): Fingerprint firmware ----------------------------------
        fingerprint = None
        try:
            fingerprint = fingerprint_firmware(firmware)
            logger.info(
                "Fingerprint: rtos=%s mcu=%s arch=%s confidence=%.2f",
                fingerprint.rtos_type,
                fingerprint.mcu_family,
                fingerprint.architecture,
                fingerprint.confidence,
            )
        except Exception as exc:
            logger.warning("Fingerprinting failed, continuing with defaults: %s", exc)

        # -- Step (c): Generate peripheral config ----------------------------
        try:
            generator = AutoConfigGenerator()
            pconfig, summary = generator.generate(firmware, fingerprint=fingerprint)
            logger.info(
                "Auto-config: %d models, %d intercepts, svd=%s",
                summary.get("model_count", 0),
                summary.get("intercept_count", 0),
                summary.get("svd_available", False),
            )
        except Exception as exc:
            logger.warning("Auto-config generation failed: %s", exc)
            pconfig = PeripheralConfig(models=[], intercepts=[], symbols={})
            summary = {
                "mcu_family": "unknown",
                "vendor": "unknown",
                "rtos_type": "unknown",
                "qemu_machine": self.machine_name,
                "hal_matches": 0,
                "peripheral_types": [],
                "model_count": 0,
                "intercept_count": 0,
                "svd_available": False,
                "architecture": "unknown",
                "confidence": 0.0,
            }

        # -- Step (d): Resolve QEMU machine if not already set ---------------
        if not self.machine_name or self.machine_name == "auto":
            try:
                effective_mcu = summary.get("mcu_family", "unknown")
                effective_arch = summary.get("architecture", "armv7m")
                self.machine_name = resolve_qemu_machine(effective_mcu, effective_arch)
                logger.info("Resolved QEMU machine: %s", self.machine_name)
                summary["qemu_machine"] = self.machine_name
            except Exception as exc:
                logger.warning("QEMU machine resolution failed, keeping '%s': %s", self.machine_name, exc)

        # -- Step (e): Create SVD peripheral models --------------------------
        svd_models: dict[str, SVDPeripheralModel] = {}
        try:
            from rtosploit.peripherals.svd_cache import SVDCache

            effective_mcu = summary.get("mcu_family", "unknown")
            cache = SVDCache()
            svd_device = cache.get_svd_device(effective_mcu)
            if svd_device is not None:
                for periph in svd_device.peripherals:
                    try:
                        model = SVDPeripheralModel(periph)
                        svd_models[periph.name.lower()] = model
                    except Exception as exc:
                        logger.warning("Failed to create SVD model for %s: %s", periph.name, exc)
                logger.info("Created %d SVD peripheral models", len(svd_models))
            else:
                logger.info("No SVD device available for %s", effective_mcu)
        except Exception as exc:
            logger.warning("SVD model creation failed, continuing without SVD: %s", exc)

        # -- Step (f): Build CompositeMMIOHandler ----------------------------
        # NOTE: The CompositeMMIOHandler is constructed here for diagnostics and
        # future use, but is NOT wired into the QEMU execution loop yet.
        # Routing MMIO accesses through GDB watchpoints is prohibitively expensive
        # (each watchpoint hit requires a full GDB stop-inspect-resume cycle).
        # For now, only HAL function intercepts (breakpoint-based) are active.
        # MMIO-level interception is planned for a future release using QEMU's
        # memory region callback API or a custom QEMU plugin.
        try:
            fallback = MMIOFallbackModel()
            system_regs = CortexMSystemRegisters()
            composite = CompositeMMIOHandler(
                svd_models=svd_models,
                fallback=fallback,
                system_regs=system_regs,
            )
            self._composite_mmio = composite
            logger.warning(
                "CompositeMMIOHandler built (%d SVD models) but MMIO interception "
                "is NOT active — only HAL function hooks are wired to the execution "
                "loop. GDB watchpoint-based MMIO routing is too expensive for "
                "real-time use.",
                len(svd_models),
            )
        except Exception as exc:
            logger.warning("Failed to build CompositeMMIOHandler: %s", exc)

        # -- Step (g): Instantiate HAL models and register intercepts --------
        self._models = {}
        try:
            self._models = pconfig.instantiate_models()
        except Exception as exc:
            logger.warning("Failed to instantiate HAL models: %s", exc)

        dispatcher = InterceptDispatcher(gdb)
        registered_count = 0

        for intercept in pconfig.get_intercepts():
            if intercept.address is None:
                # Try symbol table from auto-config
                symbols = pconfig.get_symbols()
                for addr, sym_name in symbols.items():
                    if sym_name == intercept.symbol or sym_name == intercept.function:
                        intercept.address = addr
                        break

            if intercept.address is None:
                logger.debug(
                    "Skipping auto-intercept %s — no address resolved",
                    intercept.function,
                )
                continue

            model = self._models.get(intercept.model_class)
            if model is None:
                logger.debug(
                    "Skipping auto-intercept %s — model class %s not instantiated",
                    intercept.function,
                    intercept.model_class,
                )
                continue

            try:
                dispatcher.register(model, intercept.function, intercept.address)
                registered_count += 1
                logger.info(
                    "Auto-registered intercept: %s @ 0x%08x -> %s",
                    intercept.function,
                    intercept.address,
                    model.name,
                )
            except (KeyError, Exception) as exc:
                logger.warning("Failed to register auto-intercept %s: %s", intercept.function, exc)

        self._dispatcher = dispatcher

        # -- Step (h): Store summary -----------------------------------------
        summary["registered_intercepts"] = registered_count
        summary["svd_model_count"] = len(svd_models)
        self._auto_summary = summary

        # -- Step (i): Print Rich summary ------------------------------------
        self._print_auto_summary(summary)

        return dispatcher

    def _print_auto_summary(self, summary: dict[str, Any]) -> None:
        """Print a Rich-formatted summary of auto-detection results."""
        try:
            from rich.console import Console
            from rich.table import Table
            from rich.panel import Panel

            console = Console()

            table = Table(show_header=False, box=None, padding=(0, 2))
            table.add_column("Key", style="bold cyan")
            table.add_column("Value")

            table.add_row("RTOS", summary.get("rtos_type", "unknown"))
            table.add_row("MCU Family", summary.get("mcu_family", "unknown"))
            table.add_row("Architecture", summary.get("architecture", "unknown"))
            table.add_row("Confidence", f"{summary.get('confidence', 0):.0%}")
            table.add_row("QEMU Machine", summary.get("qemu_machine", "unknown"))
            table.add_row("SVD Available", str(summary.get("svd_available", False)))
            table.add_row("SVD Models", str(summary.get("svd_model_count", 0)))
            table.add_row("HAL Matches", str(summary.get("hal_matches", 0)))
            table.add_row("Peripheral Types", ", ".join(summary.get("peripheral_types", [])) or "none")
            table.add_row("Models", str(summary.get("model_count", 0)))
            table.add_row("Intercepts (config)", str(summary.get("intercept_count", 0)))
            table.add_row("Intercepts (registered)", str(summary.get("registered_intercepts", 0)))

            panel = Panel(table, title="[bold]Auto-Rehosting Summary[/bold]", border_style="green")
            console.print(panel)
        except ImportError:
            # Rich not available — fall back to plain logging
            logger.info("=== Auto-Rehosting Summary ===")
            for key in ("rtos_type", "mcu_family", "architecture", "confidence",
                        "qemu_machine", "svd_available", "svd_model_count",
                        "hal_matches", "model_count", "intercept_count",
                        "registered_intercepts"):
                logger.info("  %s: %s", key, summary.get(key, "unknown"))
        except Exception as exc:
            logger.warning("Failed to print auto-detection summary: %s", exc)

    def get_auto_summary(self) -> dict[str, Any]:
        """Return the auto-detection summary dict.

        Contains keys: mcu_family, vendor, rtos_type, qemu_machine,
        hal_matches, peripheral_types, model_count, intercept_count,
        svd_available, architecture, confidence, registered_intercepts,
        svd_model_count.

        Returns an empty dict if auto_setup has not been called.
        """
        return dict(self._auto_summary)

    @property
    def composite_mmio(self) -> CompositeMMIOHandler | None:
        """Access the CompositeMMIOHandler built by auto_setup (for diagnostics).

        Returns None if auto_setup has not been called or handler creation failed.
        """
        return self._composite_mmio

    def run_interactive(self, qemu: QEMUInstance, timeout: int = 0) -> None:
        """Run firmware with intercept handling (non-fuzzing mode).

        Boots QEMU, sets up intercepts, then enters a continue-wait-dispatch loop.
        """
        gdb = qemu.gdb
        if gdb is None:
            raise RuntimeError("GDB connection required")

        dispatcher = self.setup(qemu)

        logger.info(
            "Rehosting engine ready: %d intercepts registered",
            len(dispatcher.registered_addresses),
        )

        start_time = time.monotonic()
        gdb.continue_execution()

        try:
            while True:
                if timeout > 0 and (time.monotonic() - start_time) >= timeout:
                    logger.info("Rehosting timeout reached (%ds)", timeout)
                    break

                try:
                    stop_reply = gdb.receive_stop(timeout=1.0)
                except TimeoutError:
                    continue

                # Read PC to determine stop address
                regs = gdb.read_registers()
                stop_addr = regs.get("pc", 0)

                if dispatcher.handle_breakpoint(stop_addr):
                    # Intercepted — resume
                    gdb.continue_execution()
                else:
                    # Not one of ours — could be a crash or user breakpoint
                    logger.info(
                        "Unhandled stop at PC=0x%08x (reply=%s)",
                        stop_addr,
                        stop_reply,
                    )
                    break

        except KeyboardInterrupt:
            logger.info("Rehosting interrupted by user")
        finally:
            gdb.send_break()
            try:
                gdb.receive_stop(timeout=1.0)
            except (TimeoutError, Exception):
                pass

    @property
    def dispatcher(self) -> InterceptDispatcher | None:
        return self._dispatcher

    @property
    def models(self) -> dict[str, PeripheralModel]:
        return dict(self._models)
