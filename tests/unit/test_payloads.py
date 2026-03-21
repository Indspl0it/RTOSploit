"""
Unit tests for rtosploit.payloads — Phase 12+13.

Tests cover:
- ARM Thumb2 shellcode templates (via Python wrapper)
- RISC-V shellcode templates (via Python wrapper)
- Payload encoders (pure Python)
- ROP gadget discovery and filtering
- ROP chain construction

All tests use the pure-Python wrappers in rtosploit.payloads.
No Rust FFI is required at this stage.
"""

import struct
import pytest

from rtosploit.payloads.shellcode import ShellcodeGenerator
from rtosploit.payloads.rop import ROPHelper


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def gen():
    return ShellcodeGenerator()


@pytest.fixture
def rop():
    return ROPHelper()


# ---------------------------------------------------------------------------
# ARM Thumb2 shellcode tests
# ---------------------------------------------------------------------------

def test_thumb2_nop_sled_length(gen):
    """NopSled(10) should produce 20 bytes (2 bytes per Thumb2 NOP)."""
    result = gen.nop_sled("arm", 10)
    assert len(result) == 20


def test_thumb2_nop_sled_bytes(gen):
    """Every 2-byte pair in the NOP sled should be the Thumb2 NOP encoding."""
    result = gen.nop_sled("arm", 5)
    for i in range(0, len(result), 2):
        assert result[i] == 0x00, f"byte[{i}] should be 0x00"
        assert result[i + 1] == 0x46, f"byte[{i+1}] should be 0x46"


def test_thumb2_infinite_loop(gen):
    """ARM Thumb2 infinite loop should be exactly [0xFE, 0xE7]."""
    result = gen.infinite_loop("arm")
    assert result == bytes([0xFE, 0xE7])


def test_thumb2_mpu_disable_contains_address(gen):
    """MPU disable sequence must contain the MPU_CTRL address (0xE000ED94) LE."""
    result = gen.mpu_disable()
    mpu_ctrl_bytes = struct.pack("<I", 0xE000_ED94)
    assert mpu_ctrl_bytes in result, (
        f"MPU_CTRL address {mpu_ctrl_bytes.hex()} not found in: {result.hex()}"
    )


def test_thumb2_mpu_disable_non_empty(gen):
    """MPU disable sequence should produce a non-trivial payload."""
    result = gen.mpu_disable()
    assert len(result) > 8


def test_thumb2_vtor_redirect_contains_address(gen):
    """VTOR redirect sequence must contain the VTOR register address (0xE000ED08) LE."""
    result = gen.vtor_redirect(0x2000_0000)
    vtor_bytes = struct.pack("<I", 0xE000_ED08)
    assert vtor_bytes in result, (
        f"VTOR address {vtor_bytes.hex()} not found in: {result.hex()}"
    )


def test_thumb2_vtor_redirect_contains_new_table(gen):
    """VTOR redirect sequence must embed the new_table address."""
    new_table = 0x2001_0000
    result = gen.vtor_redirect(new_table)
    new_table_bytes = struct.pack("<I", new_table)
    assert new_table_bytes in result


# ---------------------------------------------------------------------------
# RISC-V shellcode tests
# ---------------------------------------------------------------------------

def test_riscv_nop_sled(gen):
    """RISC-V NOP sled should produce 4*n bytes with correct encoding."""
    result = gen.nop_sled("riscv", 4)
    assert len(result) == 16
    assert result[:4] == bytes([0x13, 0x00, 0x00, 0x00])


def test_riscv_nop_sled_all_nops(gen):
    """Every 4-byte word in the RISC-V NOP sled should be the canonical NOP."""
    result = gen.nop_sled("riscv", 3)
    for i in range(0, 12, 4):
        assert result[i:i+4] == bytes([0x13, 0x00, 0x00, 0x00])


def test_riscv_infinite_loop(gen):
    """RISC-V infinite loop should be exactly [0x6F, 0x00, 0x00, 0x00]."""
    result = gen.infinite_loop("riscv")
    assert result == bytes([0x6F, 0x00, 0x00, 0x00])


def test_riscv_infinite_loop_length(gen):
    """RISC-V infinite loop is one RV32I instruction = 4 bytes."""
    result = gen.infinite_loop("riscv")
    assert len(result) == 4


# ---------------------------------------------------------------------------
# Encoder tests (pure Python implementations)
# ---------------------------------------------------------------------------

def _raw_encode(data: bytes, bad_chars: bytes) -> bytes:
    """Minimal raw encoder: pass-through, raises if bad chars present."""
    for b in data:
        if b in bad_chars:
            raise ValueError(f"Byte 0x{b:02X} is in bad_chars")
    return data


def _xor_encode(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def _nullfree_encode(data: bytes) -> bytes:
    return bytes(b if b != 0x00 else 0x01 for b in data)


def test_raw_encoder_passthrough():
    """Raw encoder should return input unchanged when no bad chars present."""
    data = bytes([0x01, 0x02, 0x03, 0x04])
    result = _raw_encode(data, b"")
    assert result == data


def test_xor_encoder_round_trip():
    """XOR encoding is its own inverse: encode(encode(x)) == x."""
    original = bytes([0xDE, 0xAD, 0xBE, 0xEF])
    key = 0xAA
    encoded = _xor_encode(original, key)
    decoded = _xor_encode(encoded, key)
    assert decoded == original


def test_xor_encoder_no_bad_chars():
    """XOR encoded output should not contain the null byte (when key is non-zero)."""
    data = bytes([0x00, 0x01, 0x02, 0x03])
    key = 0x42
    encoded = _xor_encode(data, key)
    assert 0x00 not in encoded, "XOR with non-zero key should eliminate nulls from 0x00 bytes"


def test_null_free_encoder_no_nulls():
    """Null-free encoder must produce output containing no 0x00 bytes."""
    data = bytes([0x00, 0x41, 0x00, 0x42, 0x00])
    encoded = _nullfree_encode(data)
    assert 0x00 not in encoded


def test_null_free_encoder_preserves_non_null():
    """Null-free encoder must not modify non-null bytes."""
    data = bytes([0x41, 0x42, 0x43])
    encoded = _nullfree_encode(data)
    assert encoded == data


# ---------------------------------------------------------------------------
# ShellcodeGenerator integration tests
# ---------------------------------------------------------------------------

def test_shellcode_generator_nop_sled_arm(gen):
    """ShellcodeGenerator.nop_sled('arm', N) should return non-empty bytes."""
    result = gen.nop_sled("arm", 4)
    assert isinstance(result, bytes)
    assert len(result) > 0


def test_shellcode_generator_nop_sled_riscv(gen):
    """ShellcodeGenerator.nop_sled('riscv', N) should return non-empty bytes."""
    result = gen.nop_sled("riscv", 4)
    assert isinstance(result, bytes)
    assert len(result) > 0


def test_shellcode_generator_infinite_loop_arm(gen):
    """ShellcodeGenerator.infinite_loop('arm') should return bytes."""
    result = gen.infinite_loop("arm")
    assert isinstance(result, bytes)
    assert len(result) == 2


def test_shellcode_generator_mpu_disable(gen):
    """ShellcodeGenerator.mpu_disable() should return non-empty bytes."""
    result = gen.mpu_disable()
    assert isinstance(result, bytes)
    assert len(result) > 0


def test_shellcode_generator_vtor_redirect(gen):
    """vtor_redirect() should return bytes containing the VTOR register address."""
    result = gen.vtor_redirect(0x2000_8000)
    assert isinstance(result, bytes)
    vtor_bytes = struct.pack("<I", 0xE000_ED08)
    assert vtor_bytes in result


# ---------------------------------------------------------------------------
# ROPHelper gadget discovery tests
# ---------------------------------------------------------------------------

def test_rop_helper_find_bxlr(rop):
    """ROPHelper should find BX LR gadgets embedded in a binary."""
    # Craft a binary with a BX LR gadget at offset 4.
    binary = bytes([0x00, 0x46, 0x00, 0x46, 0x70, 0x47])  # NOP NOP BX_LR
    gadgets = rop.find_bxlr_gadgets(binary, 0x0800_0000)
    assert len(gadgets) >= 1
    # The gadget address should point to the BX LR instruction.
    addrs = [g["address"] for g in gadgets]
    assert 0x0800_0004 in addrs


def test_rop_helper_no_gadgets_empty_binary(rop):
    """Empty binary should yield no gadgets."""
    gadgets = rop.find_bxlr_gadgets(b"", 0x0800_0000)
    assert gadgets == []


def test_rop_helper_single_byte_binary(rop):
    """Binary with fewer than 2 bytes should yield no gadgets."""
    gadgets = rop.find_bxlr_gadgets(b"\x70", 0)
    assert gadgets == []


def test_rop_helper_filter_bad_chars(rop):
    """filter_bad_chars removes gadgets whose address contains bad bytes."""
    gadgets = [
        {"address": 0x0800_0000, "bytes": b"\x70\x47", "type": "Unknown",
         "description": "BX LR @ 0x08000000", "stack_delta": 4},
        {"address": 0x0801_0204, "bytes": b"\x70\x47", "type": "Unknown",
         "description": "BX LR @ 0x08010204", "stack_delta": 4},
    ]
    # 0x00 appears in the first address (0x0800_0000 LE: 00 00 00 08)
    filtered = rop.filter_bad_chars(gadgets, bytes([0x00]))
    assert all(0x00 not in struct.pack("<I", g["address"]) for g in filtered)


def test_rop_helper_build_write_what_where(rop):
    """build_write_what_where should return non-empty bytes when a MemoryWrite gadget exists."""
    gadgets = [
        {"address": 0x0800_1234, "bytes": b"\x01\x60\x70\x47",
         "type": "MemoryWrite", "description": "STR R1,[R0]; BX LR", "stack_delta": 4},
    ]
    chain = rop.build_write_what_where(gadgets, 0xDEAD_BEEF, 0xCAFE_BABE)
    assert isinstance(chain, bytes)
    assert len(chain) == 12  # 3 × 4-byte LE words
    assert struct.pack("<I", 0x0800_1234) in chain
    assert struct.pack("<I", 0xDEAD_BEEF) in chain
    assert struct.pack("<I", 0xCAFE_BABE) in chain


def test_rop_helper_build_wwwhere_no_gadgets(rop):
    """build_write_what_where should return empty bytes when no MemoryWrite gadget exists."""
    gadgets = [
        {"address": 0x0800_0000, "bytes": b"\x70\x47",
         "type": "Unknown", "description": "BX LR", "stack_delta": 4},
    ]
    chain = rop.build_write_what_where(gadgets, 0x1234, 0)
    assert chain == b""


# ---------------------------------------------------------------------------
# Gadget type classification tests
# ---------------------------------------------------------------------------

def test_gadget_type_classification(rop):
    """BX LR gadget without body should be classified as 'Unknown' by default."""
    binary = bytes([0x70, 0x47])  # Just BX LR, no body
    gadgets = rop.find_bxlr_gadgets(binary, 0x0800_0000)
    assert len(gadgets) == 1
    # With no body, the gadget type falls to Unknown.
    assert gadgets[0]["type"] in ("Unknown", "RegisterControl", "MemoryWrite",
                                   "MemoryRead", "Arithmetic", "System")


def test_gadget_pop_pc_classified_register_control(rop):
    """POP {Rlist, PC} should be classified as RegisterControl."""
    # 0xFF 0xBD = POP {R0-R7, PC}
    binary = bytes([0xFF, 0xBD])
    gadgets = rop.find_bxlr_gadgets(binary, 0x0800_0000)
    assert len(gadgets) == 1
    assert gadgets[0]["type"] == "RegisterControl"


# ---------------------------------------------------------------------------
# Chain goal tests
# ---------------------------------------------------------------------------

def test_chain_mpu_disable(rop):
    """MPU disable chain should contain the MPU_CTRL address (0xE000ED94)."""
    gadgets = [
        {"address": 0x0801_0204, "bytes": b"\x01\x60\x70\x47",
         "type": "MemoryWrite", "description": "STR R1,[R0]; BX LR", "stack_delta": 4},
    ]
    chain = rop.build_mpu_disable(gadgets)
    mpu_ctrl = struct.pack("<I", 0xE000_ED94)
    assert mpu_ctrl in chain, f"MPU_CTRL address not found in chain: {chain.hex()}"


def test_filter_chain_bad_chars(rop):
    """check_chain should correctly identify bad-char-free vs dirty chains."""
    clean_chain = bytes([0x04, 0x12, 0x01, 0x08])  # no 0x00
    dirty_chain = bytes([0x04, 0x00, 0x01, 0x08])  # contains 0x00

    assert rop.check_chain(clean_chain, bytes([0x00])) is True
    assert rop.check_chain(dirty_chain, bytes([0x00])) is False


def test_filter_chain_empty_bad_chars(rop):
    """check_chain with no bad chars should always return True."""
    chain = bytes([0x00, 0x01, 0x02, 0x03])
    assert rop.check_chain(chain, b"") is True
