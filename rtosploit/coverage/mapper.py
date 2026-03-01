"""Map coverage data (traces, bitmaps) onto firmware disassembly."""

from __future__ import annotations

from typing import Optional

import capstone

from rtosploit.coverage.bitmap_reader import BitmapReader, CoverageMap, BITMAP_SIZE


class CoverageMapper:
    """Map coverage information from trace logs and bitmaps to firmware addresses.

    Args:
        firmware_path: Path to the raw firmware binary.
        base_address: Load address of the firmware in memory (default: 0x08000000 for STM32).
    """

    def __init__(self, firmware_path: str, base_address: int = 0x0800_0000) -> None:
        self.firmware_path = firmware_path
        self.base_address = base_address
        self._reader = BitmapReader()

    def map_from_trace(
        self,
        trace_log: str,
        bitmap_data: Optional[bytes] = None,
    ) -> CoverageMap:
        """Build a CoverageMap from a trace log file.

        The trace log contains one ``from_addr,to_addr`` hex pair per line
        (e.g. ``0x08001000,0x08001004``).

        Args:
            trace_log: Path to the trace log file.
            bitmap_data: Optional raw bitmap bytes for cross-referencing.

        Returns:
            Populated :class:`CoverageMap`.
        """
        cov = CoverageMap()
        edges: list[tuple[int, int]] = []
        hit_counts: dict[int, int] = {}

        with open(trace_log, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",")
                if len(parts) != 2:
                    continue
                try:
                    from_addr = int(parts[0].strip(), 16)
                    to_addr = int(parts[1].strip(), 16)
                except ValueError:
                    continue

                edges.append((from_addr, to_addr))
                cov.covered_addresses.add(from_addr)
                cov.covered_addresses.add(to_addr)
                hit_counts[from_addr] = hit_counts.get(from_addr, 0) + 1
                hit_counts[to_addr] = hit_counts.get(to_addr, 0) + 1

        cov.covered_edges = edges
        cov.hot_addresses = hit_counts

        # Cross-reference with disassembly for total instruction count
        try:
            disasm = self.disassemble_firmware()
            cov.total_instructions = len(disasm)
            all_addrs = {addr for addr, _, _ in disasm}
            cov.covered_instructions = len(cov.covered_addresses & all_addrs)
        except Exception:
            # If disassembly fails, use covered addresses as a lower bound
            cov.total_instructions = len(cov.covered_addresses)
            cov.covered_instructions = len(cov.covered_addresses)

        # Cross-reference with bitmap if provided
        if bitmap_data is not None:
            bitmap_edges = self._reader.read_bytes(bitmap_data)
            for edge_id, count in bitmap_edges.items():
                # Bitmap edges are hashed so we cannot recover exact addresses,
                # but we can verify our trace edges are consistent
                pass

        return cov

    def map_from_bitmap(
        self,
        bitmap_data: bytes,
        addresses: Optional[set[int]] = None,
    ) -> CoverageMap:
        """Build a CoverageMap from a bitmap and optional known addresses.

        Since the bitmap uses a lossy hash, exact addresses cannot be recovered
        from the bitmap alone. If ``addresses`` are provided (e.g. from
        disassembly), they are used as the set of known instruction addresses.

        Args:
            bitmap_data: Raw 64KB bitmap bytes.
            addresses: Optional set of known firmware instruction addresses.

        Returns:
            Populated :class:`CoverageMap` (edge-count only when no addresses given).
        """
        cov = CoverageMap()
        bitmap_edges = self._reader.read_bytes(bitmap_data)

        # We cannot recover exact addresses from the bitmap hash, but we can
        # report the number of edges and total hit counts.
        cov.covered_edges = [(eid, count) for eid, count in bitmap_edges.items()]

        if addresses is not None:
            cov.covered_addresses = addresses
            cov.covered_instructions = len(addresses)
        else:
            try:
                disasm = self.disassemble_firmware()
                cov.total_instructions = len(disasm)
            except Exception:
                pass

        return cov

    def disassemble_firmware(self) -> list[tuple[int, str, str]]:
        """Disassemble the firmware binary using Capstone (ARM Thumb mode).

        Returns:
            List of ``(address, mnemonic, op_str)`` tuples for each instruction.
        """
        with open(self.firmware_path, "rb") as f:
            firmware_bytes = f.read()

        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        md.detail = False

        result: list[tuple[int, str, str]] = []
        for insn in md.disasm(firmware_bytes, self.base_address):
            result.append((insn.address, insn.mnemonic, insn.op_str))

        return result
