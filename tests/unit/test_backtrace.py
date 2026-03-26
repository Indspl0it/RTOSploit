"""Tests for ARM Cortex-M stack unwinding."""

import struct


from rtosploit.emulation.backtrace import (
    StackFrame,
    format_backtrace,
    unwind_stack,
)


class MockMemoryReader:
    """Mock memory backed by a sparse dict of address -> byte value."""

    def __init__(self, words: dict[int, int] | None = None):
        self._memory: dict[int, int] = {}
        if words:
            for addr, value in words.items():
                self._write_u32(addr, value)

    def _write_u32(self, address: int, value: int) -> None:
        packed = struct.pack("<I", value)
        for i, b in enumerate(packed):
            self._memory[address + i] = b

    def read_memory(self, address: int, size: int) -> bytes:
        result = bytearray(size)
        for i in range(size):
            addr = address + i
            if addr in self._memory:
                result[i] = self._memory[addr]
        return bytes(result)


CODE_START = 0x08000000
CODE_END = 0x08FFFFFF
STACK_START = 0x20000000
STACK_END = 0x2007FFFF
CODE_RANGE = (CODE_START, CODE_END)
STACK_RANGE = (STACK_START, STACK_END)


class TestFramePointerChain:
    """Test unwinding via r7 frame pointer chain."""

    def test_three_frame_chain(self):
        fp0 = 0x20001000
        fp1 = 0x20001020
        fp2 = 0x20001040

        reader = MockMemoryReader(
            {
                fp0: fp1,
                fp0 + 4: 0x08001001,
                fp1: fp2,
                fp1 + 4: 0x08002001,
                fp2: 0,
                fp2 + 4: 0x08003001,
            }
        )

        registers = {
            "pc": 0x08000101,
            "lr": 0x08000201,
            "sp": 0x20000FF0,
            "r7": fp0,
        }

        frames = unwind_stack(
            reader,
            registers,
            code_range=CODE_RANGE,
            stack_range=STACK_RANGE,
        )

        assert len(frames) >= 3
        assert frames[0].address == 0x08000100
        assert frames[1].address == 0x08000200

    def test_four_frame_chain(self):
        fp0 = 0x20001000
        fp1 = 0x20001020
        fp2 = 0x20001040
        fp3 = 0x20001060

        reader = MockMemoryReader(
            {
                fp0: fp1,
                fp0 + 4: 0x08001001,
                fp1: fp2,
                fp1 + 4: 0x08002001,
                fp2: fp3,
                fp2 + 4: 0x08003001,
                fp3: 0,
                fp3 + 4: 0x08004001,
            }
        )

        registers = {
            "pc": 0x08000101,
            "lr": 0x08000201,
            "sp": 0x20000FF0,
            "r7": fp0,
        }

        frames = unwind_stack(
            reader,
            registers,
            code_range=CODE_RANGE,
            stack_range=STACK_RANGE,
        )

        assert len(frames) >= 4
        assert frames[0].address == 0x08000100

    def test_chain_stops_on_invalid_fp(self):
        fp0 = 0x20001000

        reader = MockMemoryReader(
            {
                fp0: 0xDEADBEEF,
                fp0 + 4: 0x08001001,
            }
        )

        registers = {
            "pc": 0x08000101,
            "lr": 0x08000201,
            "sp": 0x20000FF0,
            "r7": fp0,
        }

        frames = unwind_stack(
            reader,
            registers,
            code_range=CODE_RANGE,
            stack_range=STACK_RANGE,
        )

        assert len(frames) >= 2
        assert len(frames) <= 4


class TestStackScanFallback:
    """Test stack scanning when no valid r7 chain exists."""

    def test_scan_finds_return_addresses(self):
        sp = 0x20001000
        reader = MockMemoryReader(
            {
                sp: 0x00000000,
                sp + 4: 0x08001001,
                sp + 8: 0x00000000,
                sp + 12: 0x08002001,
                sp + 16: 0x08003001,
            }
        )

        registers = {
            "pc": 0x08000101,
            "lr": 0xFFFFFFFF,  # Invalid LR forces stack scan fallback
            "sp": sp,
            "r7": 0x00000000,
        }

        frames = unwind_stack(
            reader,
            registers,
            code_range=CODE_RANGE,
            stack_range=STACK_RANGE,
        )

        assert len(frames) >= 3
        addresses = {f.address for f in frames}
        assert 0x08000100 in addresses

    def test_scan_deduplicates_consecutive(self):
        sp = 0x20001000
        reader = MockMemoryReader(
            {
                sp: 0x08001001,
                sp + 4: 0x08001001,
                sp + 8: 0x08002001,
            }
        )

        registers = {
            "pc": 0x08000101,
            "lr": 0x08000201,
            "sp": sp,
            "r7": 0x00000000,
        }

        frames = unwind_stack(
            reader,
            registers,
            code_range=CODE_RANGE,
            stack_range=STACK_RANGE,
        )

        addresses = [f.address for f in frames]
        assert addresses.count(0x08001000) <= 1


class TestSymbolResolution:
    """Test that symbols are resolved in backtrace frames."""

    def test_symbols_appear_in_frames(self):
        sp = 0x20001000
        reader = MockMemoryReader(
            {
                sp: 0x08001001,
                sp + 4: 0x08002001,
            }
        )

        symbols = {
            "main": 0x08000100,
            "uart_handler": 0x08000200,
            "timer_isr": 0x08001000,
        }

        registers = {
            "pc": 0x08000101,
            "lr": 0x08000201,
            "sp": sp,
            "r7": 0x00000000,
        }

        frames = unwind_stack(
            reader,
            registers,
            symbols=symbols,
            code_range=CODE_RANGE,
            stack_range=STACK_RANGE,
        )

        assert frames[0].function == "main"
        assert frames[1].function == "uart_handler"

    def test_no_symbols_graceful(self):
        reader = MockMemoryReader()
        registers = {
            "pc": 0x08000101,
            "lr": 0x08000201,
            "sp": 0x20001000,
            "r7": 0x00000000,
        }

        frames = unwind_stack(
            reader,
            registers,
            symbols=None,
            code_range=CODE_RANGE,
            stack_range=STACK_RANGE,
        )

        assert len(frames) >= 1
        assert frames[0].function == ""


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_invalid_sp_outside_range(self):
        reader = MockMemoryReader()
        registers = {
            "pc": 0x08000101,
            "lr": 0x08000201,
            "sp": 0x10000000,
            "r7": 0x00000000,
        }

        frames = unwind_stack(
            reader,
            registers,
            code_range=CODE_RANGE,
            stack_range=STACK_RANGE,
        )

        assert len(frames) <= 2

    def test_max_frames_limit(self):
        fp_base = 0x20001000
        words: dict[int, int] = {}
        for i in range(50):
            fp = fp_base + i * 0x20
            next_fp = fp_base + (i + 1) * 0x20
            words[fp] = next_fp
            words[fp + 4] = 0x08000001 + i * 0x100

        reader = MockMemoryReader(words)

        registers = {
            "pc": 0x08000101,
            "lr": 0x08000201,
            "sp": 0x20000FF0,
            "r7": fp_base,
        }

        frames = unwind_stack(
            reader,
            registers,
            max_frames=5,
            code_range=CODE_RANGE,
            stack_range=STACK_RANGE,
        )

        assert len(frames) <= 5

    def test_empty_registers(self):
        reader = MockMemoryReader()
        frames = unwind_stack(reader, {})
        assert frames == []

    def test_missing_pc(self):
        reader = MockMemoryReader()
        registers = {"lr": 0x08000201, "sp": 0x20001000, "r7": 0x20001000}

        frames = unwind_stack(
            reader,
            registers,
            code_range=CODE_RANGE,
            stack_range=STACK_RANGE,
        )

        assert frames == []

    def test_lr_outside_code_range(self):
        reader = MockMemoryReader()
        registers = {
            "pc": 0x08000101,
            "lr": 0xFFFFFFFF,
            "sp": 0x20001000,
            "r7": 0x00000000,
        }

        frames = unwind_stack(
            reader,
            registers,
            code_range=CODE_RANGE,
            stack_range=STACK_RANGE,
        )

        assert len(frames) >= 1
        assert frames[0].address == 0x08000100


class TestStackFrame:
    """Test StackFrame dataclass."""

    def test_str_with_function(self):
        frame = StackFrame(address=0x08000100, sp=0x20001000, function="main")
        assert "main" in str(frame)
        assert "0x08000100" in str(frame)

    def test_str_without_function(self):
        frame = StackFrame(address=0x08000100, sp=0x20001000)
        assert "0x08000100" in str(frame)
        assert "<" not in str(frame)


class TestFormatBacktrace:
    """Test backtrace formatting."""

    def test_format_with_frames(self):
        frames = [
            StackFrame(address=0x08000100, sp=0x20001000, function="main"),
            StackFrame(address=0x08000200, sp=0x20001010, function="foo"),
        ]
        result = format_backtrace(frames)
        assert "#0:" in result
        assert "#1:" in result
        assert "main" in result
        assert "foo" in result

    def test_format_empty(self):
        result = format_backtrace([])
        assert "no backtrace available" in result

    def test_format_single_frame(self):
        frames = [StackFrame(address=0x08000100, sp=0x20001000)]
        result = format_backtrace(frames)
        assert "#0:" in result
        assert "0x08000100" in result
