"""Tests for PIP (Peripheral Input Playback) handler.

Tests cover PeripheralMemoryStore, ReplayBitsBuffer, PIPHandler,
and CompositeMMIOHandler integration with PIP.

Based on: Farrelly, Chesser, Ranasinghe. "Ember-IO: Effective Firmware
Fuzzing with Model-Free Memory Mapped IO." ASIA CCS 2023.
https://doi.org/10.1145/3579856.3582840
"""

from __future__ import annotations

import struct

import pytest

from rtosploit.fuzzing.fuzz_input import FuzzInputStream, InputExhausted
from rtosploit.peripherals.pip_handler import (
    PIPHandler,
    PIPStats,
    PeripheralMemoryStore,
    ReplayBitsBuffer,
)


# ---------------------------------------------------------------------------
# PeripheralMemoryStore
# ---------------------------------------------------------------------------

class TestPeripheralMemoryStore:
    """Tests for PeripheralMemoryStore."""

    def test_get_unknown_address_returns_zero(self):
        store = PeripheralMemoryStore()
        assert store.get(0x40000000) == 0

    def test_set_and_get(self):
        store = PeripheralMemoryStore()
        store.set(0x40000000, 0xDEADBEEF)
        assert store.get(0x40000000) == 0xDEADBEEF

    def test_overwrite(self):
        store = PeripheralMemoryStore()
        store.set(0x40000000, 1)
        store.set(0x40000000, 2)
        assert store.get(0x40000000) == 2

    def test_has_false_initially(self):
        store = PeripheralMemoryStore()
        assert store.has(0x40000000) is False

    def test_has_true_after_set(self):
        store = PeripheralMemoryStore()
        store.set(0x40000000, 42)
        assert store.has(0x40000000) is True

    def test_clear(self):
        store = PeripheralMemoryStore()
        store.set(0x40000000, 1)
        store.set(0x40000004, 2)
        store.clear()
        assert store.has(0x40000000) is False
        assert store.has(0x40000004) is False
        assert store.get(0x40000000) == 0

    def test_addresses(self):
        store = PeripheralMemoryStore()
        store.set(0x40000008, 1)
        store.set(0x40000000, 2)
        store.set(0x40000004, 3)
        assert store.addresses() == [0x40000000, 0x40000004, 0x40000008]

    def test_addresses_empty(self):
        store = PeripheralMemoryStore()
        assert store.addresses() == []

    def test_access_count(self):
        store = PeripheralMemoryStore()
        assert store.access_count(0x40000000) == 0
        store.set(0x40000000, 1)
        assert store.access_count(0x40000000) == 1
        store.set(0x40000000, 2)
        assert store.access_count(0x40000000) == 2

    def test_multiple_addresses_independent(self):
        store = PeripheralMemoryStore()
        store.set(0x40000000, 0xAA)
        store.set(0x40000004, 0xBB)
        assert store.get(0x40000000) == 0xAA
        assert store.get(0x40000004) == 0xBB


# ---------------------------------------------------------------------------
# ReplayBitsBuffer
# ---------------------------------------------------------------------------

class TestReplayBitsBuffer:
    """Tests for ReplayBitsBuffer."""

    def test_needs_refill_initially(self):
        buf = ReplayBitsBuffer()
        assert buf.needs_refill(0x40000000) is True

    def test_all_replay_0xFFFFFFFF(self):
        """0xFFFFFFFF = all bits 11 -> all 16 reads should replay."""
        buf = ReplayBitsBuffer()
        fuzz = FuzzInputStream(struct.pack("<I", 0xFFFFFFFF))
        for _ in range(16):
            assert buf.should_replay(0x40000000, fuzz) is True

    def test_no_replay_0x00000000(self):
        """0x00000000 = all bits 00 -> no reads should replay."""
        buf = ReplayBitsBuffer()
        fuzz = FuzzInputStream(struct.pack("<I", 0x00000000))
        for _ in range(16):
            assert buf.should_replay(0x40000000, fuzz) is False

    def test_first_replay_only_0x00000003(self):
        """0x00000003 = bottom 2 bits are 11 -> first read replays, rest don't."""
        buf = ReplayBitsBuffer()
        fuzz = FuzzInputStream(struct.pack("<I", 0x00000003))
        assert buf.should_replay(0x40000000, fuzz) is True
        for _ in range(15):
            assert buf.should_replay(0x40000000, fuzz) is False

    def test_mixed_pattern(self):
        """0x0000000F = bits 11 11 00 00 ... -> first 2 replay, rest don't."""
        buf = ReplayBitsBuffer()
        fuzz = FuzzInputStream(struct.pack("<I", 0x0000000F))
        assert buf.should_replay(0x40000000, fuzz) is True   # bits 11
        assert buf.should_replay(0x40000000, fuzz) is True   # bits 11
        assert buf.should_replay(0x40000000, fuzz) is False  # bits 00
        for _ in range(13):
            assert buf.should_replay(0x40000000, fuzz) is False

    def test_refill_after_16_reads(self):
        """After 16 reads, needs_refill becomes True and new word is read."""
        # Two 32-bit words: first all-replay, second all-no-replay
        data = struct.pack("<II", 0xFFFFFFFF, 0x00000000)
        buf = ReplayBitsBuffer()
        fuzz = FuzzInputStream(data)

        # First 16: all replay
        for _ in range(16):
            assert buf.should_replay(0x40000000, fuzz) is True

        # Needs refill now
        assert buf.needs_refill(0x40000000) is True

        # Next 16: all no-replay (auto-refills from stream)
        for _ in range(16):
            assert buf.should_replay(0x40000000, fuzz) is False

    def test_per_register_independence(self):
        """Each register address has its own replay buffer."""
        data = struct.pack("<II", 0xFFFFFFFF, 0x00000000)
        buf = ReplayBitsBuffer()
        fuzz = FuzzInputStream(data)

        # addr1 gets 0xFFFFFFFF (all replay)
        assert buf.should_replay(0x40000000, fuzz) is True
        # addr2 gets 0x00000000 (no replay)
        assert buf.should_replay(0x40000004, fuzz) is False

    def test_reset_clears_all(self):
        buf = ReplayBitsBuffer()
        fuzz = FuzzInputStream(struct.pack("<I", 0xFFFFFFFF))
        buf.should_replay(0x40000000, fuzz)
        buf.reset()
        assert buf.needs_refill(0x40000000) is True

    def test_exhaustion_during_refill(self):
        """InputExhausted raised when not enough bytes for replay word."""
        buf = ReplayBitsBuffer()
        fuzz = FuzzInputStream(b"\x01\x02")  # Only 2 bytes, need 4
        with pytest.raises(InputExhausted):
            buf.should_replay(0x40000000, fuzz)


# ---------------------------------------------------------------------------
# PIPStats
# ---------------------------------------------------------------------------

class TestPIPStats:
    """Tests for PIPStats dataclass."""

    def test_defaults_zero(self):
        stats = PIPStats()
        assert stats.total_reads == 0
        assert stats.total_writes == 0
        assert stats.replay_count == 0
        assert stats.new_value_count == 0

    def test_replay_percentage_zero_reads(self):
        stats = PIPStats()
        assert stats.replay_percentage == 0.0

    def test_replay_percentage(self):
        stats = PIPStats(total_reads=40, replay_count=10)
        assert stats.replay_percentage == 25.0

    def test_to_dict(self):
        stats = PIPStats(total_reads=10, total_writes=5, replay_count=3, new_value_count=7)
        d = stats.to_dict()
        assert d["total_reads"] == 10
        assert d["total_writes"] == 5
        assert d["replay_count"] == 3
        assert d["new_value_count"] == 7
        assert d["replay_percentage"] == 30.0

    def test_reset(self):
        stats = PIPStats(total_reads=10, total_writes=5, replay_count=3, new_value_count=7)
        stats.reset()
        assert stats.total_reads == 0
        assert stats.total_writes == 0
        assert stats.replay_count == 0
        assert stats.new_value_count == 0


# ---------------------------------------------------------------------------
# PIPHandler
# ---------------------------------------------------------------------------

class TestPIPHandler:
    """Tests for the core PIP handler (Algorithm 1)."""

    def _make_handler(self, data: bytes) -> PIPHandler:
        """Helper: create a PIPHandler with given fuzz input."""
        return PIPHandler(FuzzInputStream(data))

    def test_all_replay_returns_zero(self):
        """All replay bits set -> returns stored value (0 by default)."""
        # 0xFFFFFFFF replay bits, no value bytes needed (all replay default 0)
        handler = self._make_handler(struct.pack("<I", 0xFFFFFFFF))
        for _ in range(16):
            assert handler.mmio_read(0x40000000, 4) == 0

    def test_new_value_read(self):
        """No replay -> reads fresh value from input."""
        # 0x00000000 replay bits (no replay) + 4-byte value
        data = struct.pack("<I", 0x00000000) + struct.pack("<I", 0xDEADBEEF)
        handler = self._make_handler(data)
        value = handler.mmio_read(0x40000000, 4)
        assert value == 0xDEADBEEF

    def test_replay_after_new_value(self):
        """Read a new value, then replay returns that same value."""
        # First: no replay for read 1 (bits 00), replay for read 2 (bits 11)
        # Bit pattern: 0b1100 = 0x0C -> bottom 2 bits = 00 (new), next 2 = 11 (replay)
        # Remaining 12 pairs = 00 (don't care)
        replay_word = 0x0000000C
        data = struct.pack("<I", replay_word) + struct.pack("<I", 0x42)
        handler = self._make_handler(data)

        # First read: new value
        val1 = handler.mmio_read(0x40000000, 4)
        assert val1 == 0x42

        # Second read: replay -> same value
        val2 = handler.mmio_read(0x40000000, 4)
        assert val2 == 0x42

    def test_write_stores_for_replay(self):
        """Firmware write followed by replay returns the written value."""
        # All replay bits set
        data = struct.pack("<I", 0xFFFFFFFF)
        handler = self._make_handler(data)

        # Write a value
        handler.mmio_write(0x40000000, 0xBEEF, 4)

        # Read with replay -> should return 0xBEEF
        val = handler.mmio_read(0x40000000, 4)
        assert val == 0xBEEF

    def test_stats_tracking(self):
        """Stats correctly track reads, writes, replays, and new values."""
        # 2 reads: first new, second replay
        replay_word = 0x0000000C  # bits: 00 (new), 11 (replay), rest 00
        data = struct.pack("<I", replay_word) + struct.pack("<I", 0x42)
        handler = self._make_handler(data)

        handler.mmio_read(0x40000000, 4)
        handler.mmio_read(0x40000000, 4)
        handler.mmio_write(0x40000004, 0x1, 4)

        stats = handler.stats
        assert stats.total_reads == 2
        assert stats.total_writes == 1
        assert stats.new_value_count == 1
        assert stats.replay_count == 1

    def test_input_exhausted_during_replay_bits(self):
        """InputExhausted raised when can't read replay bits."""
        handler = self._make_handler(b"\x01\x02")  # Only 2 bytes
        with pytest.raises(InputExhausted):
            handler.mmio_read(0x40000000, 4)

    def test_input_exhausted_during_value_read(self):
        """InputExhausted raised when replay bits read but value bytes missing."""
        # Replay bits: all 00 (need new value), but no value bytes
        data = struct.pack("<I", 0x00000000)
        handler = self._make_handler(data)
        with pytest.raises(InputExhausted):
            handler.mmio_read(0x40000000, 4)

    def test_input_exhausted_check(self):
        """InputExhausted raised when stream already exhausted before read."""
        handler = self._make_handler(b"")
        with pytest.raises(InputExhausted):
            handler.mmio_read(0x40000000, 4)

    def test_multiple_addresses(self):
        """Different addresses get independent replay buffers and stores."""
        # addr1: replay word (all replay) + addr2: no replay + value
        data = (
            struct.pack("<I", 0xFFFFFFFF)   # replay bits for addr1
            + struct.pack("<I", 0x00000000)  # replay bits for addr2
            + struct.pack("<I", 0xABCD)      # value for addr2
        )
        handler = self._make_handler(data)

        # addr1: replay -> returns 0 (default)
        assert handler.mmio_read(0x40000000, 4) == 0
        # addr2: new value
        assert handler.mmio_read(0x40000004, 4) == 0xABCD

    def test_read_u8_size(self):
        """PIP respects register size for value reads."""
        # No replay + 1-byte value
        data = struct.pack("<I", 0x00000000) + b"\xAB"
        handler = self._make_handler(data)
        val = handler.mmio_read(0x40000000, 1)
        assert val == 0xAB

    def test_read_u16_size(self):
        """PIP respects 16-bit register width."""
        data = struct.pack("<I", 0x00000000) + struct.pack("<H", 0x1234)
        handler = self._make_handler(data)
        val = handler.mmio_read(0x40000000, 2)
        assert val == 0x1234

    def test_reset_for_new_iteration(self):
        """Reset clears replay buffers and stats but takes new input."""
        old_data = struct.pack("<I", 0xFFFFFFFF)
        handler = self._make_handler(old_data)
        handler.mmio_read(0x40000000, 4)

        # Reset with new input
        new_data = struct.pack("<I", 0x00000000) + struct.pack("<I", 0x99)
        handler.reset(FuzzInputStream(new_data))

        assert handler.stats.total_reads == 0
        val = handler.mmio_read(0x40000000, 4)
        assert val == 0x99

    def test_store_accessible(self):
        """The peripheral memory store is accessible via property."""
        handler = self._make_handler(b"")
        assert handler.store is not None
        assert handler.store.addresses() == []

    def test_full_algorithm_sequence(self):
        """End-to-end test matching Ember-IO Algorithm 1 with a known sequence.

        Sequence:
        1. Read addr1 (new value 0xAAAA as u16)
        2. Read addr1 (replay -> 0xAAAA)
        3. Write addr1 <- 0xBBBB
        4. Read addr1 (replay -> 0xBBBB from write)
        """
        # Replay bits for addr1: 00 (new), 11 (replay), 11 (replay), then don't care
        # Binary: ...11_11_00 = 0x3C -> wait, let me be precise
        # Bit pairs consumed bottom-first: pair0=00, pair1=11, pair2=11
        # Word = 0b00...00_11_11_00 = 0x3C wait:
        # pair0 (bits 0-1) = 00 -> new
        # pair1 (bits 2-3) = 11 -> replay
        # pair2 (bits 4-5) = 11 -> replay
        # Word = 0b...00_11_11_00 = (3 << 2) | (3 << 4) = 12 + 48 = 60 = 0x3C
        replay_word = 0x0000003C
        value_bytes = struct.pack("<H", 0xAAAA)
        data = struct.pack("<I", replay_word) + value_bytes
        handler = self._make_handler(data)

        # Step 1: new value
        assert handler.mmio_read(0x40000000, 2) == 0xAAAA

        # Step 2: replay
        assert handler.mmio_read(0x40000000, 2) == 0xAAAA

        # Step 3: firmware write
        handler.mmio_write(0x40000000, 0xBBBB, 2)

        # Step 4: replay returns the written value
        assert handler.mmio_read(0x40000000, 2) == 0xBBBB

        # Verify stats
        assert handler.stats.total_reads == 3
        assert handler.stats.new_value_count == 1
        assert handler.stats.replay_count == 2
        assert handler.stats.total_writes == 1


# ---------------------------------------------------------------------------
# CompositeMMIOHandler with PIP integration
# ---------------------------------------------------------------------------

class TestCompositeMMIOHandlerPIP:
    """Tests for PIP integration into CompositeMMIOHandler."""

    def test_without_pip_uses_fallback(self):
        """When pip_handler is None, falls through to fallback."""
        from rtosploit.peripherals.models.mmio_fallback import CompositeMMIOHandler

        handler = CompositeMMIOHandler()
        # Fallback returns 0x00000001 (ready bit) for unknown addresses
        val = handler.read(0x40000000, 4)
        assert val == 0x00000001
        assert handler.pip_handler is None

    def test_with_pip_routes_reads(self):
        """When pip_handler is set, reads route through PIP."""
        from rtosploit.peripherals.models.mmio_fallback import CompositeMMIOHandler

        data = struct.pack("<I", 0x00000000) + struct.pack("<I", 0xCAFE)
        pip = PIPHandler(FuzzInputStream(data))
        composite = CompositeMMIOHandler(pip_handler=pip)

        val = composite.read(0x40000000, 4)
        assert val == 0xCAFE

        stats = composite.get_coverage_stats()
        assert stats["pip_handled"] == 1
        assert stats["fallback_handled"] == 0

    def test_with_pip_routes_writes(self):
        """When pip_handler is set, writes route through PIP."""
        from rtosploit.peripherals.models.mmio_fallback import CompositeMMIOHandler

        data = struct.pack("<I", 0xFFFFFFFF)  # all replay
        pip = PIPHandler(FuzzInputStream(data))
        composite = CompositeMMIOHandler(pip_handler=pip)

        composite.write(0x40000000, 0x42, 4)

        # PIP stores the write; replay should return it
        val = composite.read(0x40000000, 4)
        assert val == 0x42

    def test_system_regs_still_prioritized(self):
        """System registers (PPB) still handled before PIP."""
        from rtosploit.peripherals.models.mmio_fallback import CompositeMMIOHandler

        pip = PIPHandler(FuzzInputStream(b""))
        composite = CompositeMMIOHandler(pip_handler=pip)

        # CPUID register in PPB region
        val = composite.read(0xE000ED00, 4)
        assert val == 0x410FC241  # Cortex-M4 CPUID

        stats = composite.get_coverage_stats()
        assert stats["system_handled"] == 1
        assert stats["pip_handled"] == 0

    def test_pip_handler_property(self):
        """pip_handler property returns the handler or None."""
        from rtosploit.peripherals.models.mmio_fallback import CompositeMMIOHandler

        composite_none = CompositeMMIOHandler()
        assert composite_none.pip_handler is None

        pip = PIPHandler(FuzzInputStream(b""))
        composite_pip = CompositeMMIOHandler(pip_handler=pip)
        assert composite_pip.pip_handler is pip

    def test_coverage_stats_include_pip(self):
        """Coverage stats dict includes pip_handled key."""
        from rtosploit.peripherals.models.mmio_fallback import CompositeMMIOHandler

        composite = CompositeMMIOHandler()
        stats = composite.get_coverage_stats()
        assert "pip_handled" in stats
        assert stats["pip_handled"] == 0
