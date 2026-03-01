"""Firmware rehosting engine with peripheral model support.

Orchestrates: QEMU boot -> symbol resolution -> intercept setup -> run loop.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, TYPE_CHECKING

from rtosploit.peripherals.config import PeripheralConfig, SymbolResolver
from rtosploit.peripherals.dispatcher import InterceptDispatcher
from rtosploit.peripherals.model import PeripheralModel

if TYPE_CHECKING:
    from rtosploit.emulation.gdb import GDBClient
    from rtosploit.emulation.qemu import QEMUInstance

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
    ) -> None:
        self.firmware_path = firmware_path
        self.machine_name = machine_name
        self.peripheral_config_path = peripheral_config
        self._config = config
        self._dispatcher: InterceptDispatcher | None = None
        self._models: dict[str, PeripheralModel] = {}

    def setup(self, qemu: QEMUInstance) -> InterceptDispatcher:
        """Set up all intercepts on an already-booted QEMU instance.

        Args:
            qemu: A running QEMUInstance with GDB connected.

        Returns:
            The InterceptDispatcher ready to handle breakpoint events.
        """
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
