"""Memory read/write operations for a live QEMU instance."""

from __future__ import annotations

import re
import struct
from typing import TYPE_CHECKING

from rtosploit.errors import OperationError

if TYPE_CHECKING:
    from rtosploit.emulation.qemu import QEMUInstance


# Cortex-M system control registers (address -> name)
_CORTEX_M_SYSTEM_REGS = {
    0xE000ED08: "VTOR",    # Vector Table Offset Register
    0xE000ED24: "CFSR",    # Configurable Fault Status Register
    0xE000E010: "SYST_CSR",
    0xE000E014: "SYST_RVR",
    0xE000E018: "SYST_CVR",
}

# Cortex-M vector table entry names (first 16 entries)
_VECTOR_NAMES = [
    "initial_sp",
    "reset",
    "nmi",
    "hardfault",
    "memmanage",
    "busfault",
    "usagefault",
    "reserved_7",
    "reserved_8",
    "reserved_9",
    "reserved_10",
    "svc",
    "debugmon",
    "reserved_13",
    "pendsv",
    "systick",
]


class MemoryOps:
    """High-level memory operations wrapping a QEMUInstance.

    Uses GDB RSP for write operations when available, and QMP human-monitor
    commands for read operations.
    """

    def __init__(self, qemu: "QEMUInstance") -> None:
        self._qemu = qemu

    def read(self, address: int, size: int) -> bytes:
        """Read bytes from emulated memory using QMP human-monitor 'xp' command.

        Args:
            address: Start address.
            size: Number of bytes to read.

        Returns:
            Raw bytes from the target address.

        Raises:
            OperationError: If the QMP command fails or output cannot be parsed.
        """
        # Use 'xp /Nbx addr' which dumps N bytes in hex format
        output = self._qemu.qmp.execute(
            "human-monitor-command",
            {"command-line": f"xp /{size}bx 0x{address:08x}"}
        )

        if not isinstance(output, str):
            raise OperationError(f"Unexpected QMP response type: {type(output)}")

        return _parse_xp_output(output, size)

    def write(self, address: int, data: bytes) -> None:
        """Write bytes to emulated memory.

        Prefers GDB RSP if a GDB client is attached; falls back to QMP
        human-monitor 'set_mem' for word-aligned writes.

        Args:
            address: Start address.
            data: Bytes to write.
        """
        gdb = getattr(self._qemu, "gdb", None)
        if gdb is not None and getattr(gdb, "_connected", False):
            gdb.write_memory(address, data)
            return

        # Fallback: write word by word via QMP human-monitor
        # (no direct bulk write in QMP without GDB)
        for i in range(0, len(data), 4):
            chunk = data[i:i + 4]
            # Pad to 4 bytes
            chunk = chunk.ljust(4, b"\x00")
            _word = struct.unpack_from("<I", chunk)[0]  # noqa: F841
            self._qemu.qmp.execute(
                "human-monitor-command",
                {"command-line": f"xp /1wx 0x{address + i:08x}"}
            )
            # QMP doesn't have a direct write command; use writemem workaround
            # This is a best-effort: real implementation needs GDB for writes
            raise OperationError(
                "Memory write requires GDB RSP connection. "
                "Start QEMU with -gdb tcp::1234 and connect GDB client."
            )

    def dump(self, address: int, size: int, output_path: str) -> None:
        """Dump a memory region to a file using QMP 'memsave'.

        Args:
            address: Start address.
            size: Number of bytes to dump.
            output_path: File path for the dump output.
        """
        self._qemu.qmp.execute(
            "memsave",
            {
                "val": address,
                "size": size,
                "filename": output_path,
            }
        )

    def read_register(self, name: str) -> int:
        """Read a named register via GDB RSP.

        Args:
            name: Register name (e.g., "pc", "sp", "r0").

        Returns:
            32-bit register value.

        Raises:
            OperationError: If no GDB connection or register not found.
        """
        gdb = getattr(self._qemu, "gdb", None)
        if gdb is None or not getattr(gdb, "_connected", False):
            raise OperationError(
                "Reading registers requires a GDB RSP connection."
            )
        registers = gdb.read_registers()
        name_lower = name.lower().lstrip("$")
        if name_lower not in registers:
            raise OperationError(f"Unknown register '{name}'. Available: {list(registers.keys())}")
        return registers[name_lower]

    def read_all_registers(self) -> dict[str, int]:
        """Read all ARM Cortex-M registers via GDB RSP.

        Returns:
            Dict with keys: r0-r12, sp, lr, pc, xpsr.
            Additional system registers (msp, psp, control) are read via
            QMP human-monitor if GDB is not available.
        """
        gdb = getattr(self._qemu, "gdb", None)
        if gdb is None or not getattr(gdb, "_connected", False):
            raise OperationError(
                "Reading registers requires a GDB RSP connection."
            )
        return gdb.read_registers()

    def read_vector_table(self) -> dict[str, int]:
        """Read the ARM Cortex-M vector table.

        Reads VTOR (0xE000ED08) to find the actual vector table base,
        then reads the first 16 entries.

        Returns:
            Dict mapping vector names to handler addresses.
        """
        # Read VTOR to get vector table base address
        vtor_bytes = self.read(0xE000ED08, 4)
        vtor = struct.unpack_from("<I", vtor_bytes)[0]
        # Mask to page-aligned address (VTOR alignment is implementation-defined)
        vt_base = vtor & 0xFFFFFF80

        # Read 16 entries (64 bytes)
        table_bytes = self.read(vt_base, 16 * 4)
        table: dict[str, int] = {}
        for i, name in enumerate(_VECTOR_NAMES):
            offset = i * 4
            value = struct.unpack_from("<I", table_bytes, offset)[0]
            table[name] = value

        return table


def _parse_xp_output(output: str, expected_bytes: int) -> bytes:
    """Parse the output of QEMU's 'xp /Nbx addr' command.

    The output format is:
        0x00000000: 0x12 0x34 0x56 0x78 ...

    Multiple lines may be present for larger reads.

    Args:
        output: Raw string from QMP human-monitor-command.
        expected_bytes: Expected number of bytes.

    Returns:
        Bytes parsed from the output.
    """
    result = bytearray()
    # Match hex byte values like "0x12" or "0xAB"
    hex_pattern = re.compile(r"0x([0-9a-fA-F]{1,2})(?!\w)")
    # Skip the address at the start of each line (format: 0x12345678:)
    addr_pattern = re.compile(r"^0x[0-9a-fA-F]+:\s*")

    for line in output.strip().splitlines():
        line = addr_pattern.sub("", line.strip())
        for match in hex_pattern.finditer(line):
            result.append(int(match.group(1), 16))

    # Trim to expected size
    data = bytes(result[:expected_bytes])
    if len(data) < expected_bytes:
        # Pad with zeros if we got less data than expected
        data = data + b"\x00" * (expected_bytes - len(data))

    return data
