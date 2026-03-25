"""Unit tests for the MMIO fallback handler."""

from __future__ import annotations


import pytest

from rtosploit.peripherals.models.mmio_fallback import (
    CompositeMMIOHandler,
    CortexMSystemRegisters,
    MMIOFallbackModel,
)
from rtosploit.peripherals.models.svd_peripheral import SVDPeripheralModel
from rtosploit.peripherals.svd_model import SVDPeripheral, SVDRegister


# ---------------------------------------------------------------------------
# 1. TestMMIOFallbackModel
# ---------------------------------------------------------------------------

class TestMMIOFallbackModel:
    @pytest.fixture
    def fb(self) -> MMIOFallbackModel:
        return MMIOFallbackModel()

    def test_first_read_returns_ready_bit(self, fb: MMIOFallbackModel) -> None:
        """First read at a new address returns 0x1 (generic ready)."""
        assert fb.read_register(0x40001000) == 0x00000001

    def test_write_then_read_echo_back(self, fb: MMIOFallbackModel) -> None:
        """After writing a value, reading returns that value (echo-back)."""
        fb.write_register(0x40001000, 0xDEADBEEF)
        assert fb.read_register(0x40001000) == 0xDEADBEEF

    def test_poll_loop_returns_ready_after_100_reads(self, fb: MMIOFallbackModel) -> None:
        """After >100 reads without a write, returns 0x1 (ready bit) consistently."""
        addr = 0x40002000
        # First 100 reads return 0x1 (ready bit)
        for _ in range(100):
            fb.read_register(addr)

        # Reads 101-200 should all return 0x1 (ready)
        for _ in range(100):
            assert fb.read_register(addr) == 0x00000001

    def test_extreme_poll_loop_alternates_after_1000_reads(self, fb: MMIOFallbackModel) -> None:
        """After >1000 reads without a write, values alternate between 0 and 1."""
        addr = 0x40002000
        for _ in range(1000):
            fb.read_register(addr)

        # Reads 1001+ should alternate 0/1
        val_a = fb.read_register(addr)  # count=1001, odd -> 0
        val_b = fb.read_register(addr)  # count=1002, even -> 1
        assert val_a != val_b
        assert val_a in (0x0, 0x1)
        assert val_b in (0x0, 0x1)

    def test_write_resets_read_count(self, fb: MMIOFallbackModel) -> None:
        """Writing to an address resets the read counter."""
        addr = 0x40003000
        # Read 150 times (enters poll-loop territory)
        for _ in range(150):
            fb.read_register(addr)

        # Write resets counter
        fb.write_register(addr, 0x42)
        # Next read should return the written value (echo-back), not poll alternate
        assert fb.read_register(addr) == 0x42

    def test_access_stats_tracking(self, fb: MMIOFallbackModel) -> None:
        """Access stats report correct read/write counts per address.

        Note: write_register resets the read count for that address, so
        reads before a write are zeroed out in the stats.
        """
        fb.read_register(0x40001000)
        fb.read_register(0x40001000)
        fb.write_register(0x40001000, 0x1)  # resets read count to 0
        fb.read_register(0x40001000)  # read after write -> count=1
        fb.read_register(0x40002000)

        stats = fb.get_access_stats()
        assert stats[0x40001000]["reads"] == 1  # reset by write, then 1 more
        assert stats[0x40001000]["writes"] == 1
        assert stats[0x40002000]["reads"] == 1
        assert stats[0x40002000]["writes"] == 0

    def test_total_reads_writes(self, fb: MMIOFallbackModel) -> None:
        fb.read_register(0x40001000)
        fb.read_register(0x40002000)
        fb.write_register(0x40001000, 0x1)  # resets 0x40001000 read count to 0
        # total_reads sums current _read_counts: 0x40001000=0, 0x40002000=1
        assert fb.total_reads == 1
        assert fb.total_writes == 1

    def test_unhandled_addresses_list(self, fb: MMIOFallbackModel) -> None:
        """get_unhandled_addresses returns sorted list of all accessed addresses."""
        fb.read_register(0x40003000)
        fb.write_register(0x40001000, 0x1)
        fb.read_register(0x40002000)

        addrs = fb.get_unhandled_addresses()
        assert addrs == [0x40001000, 0x40002000, 0x40003000]

    def test_access_log_records_entries(self, fb: MMIOFallbackModel) -> None:
        fb.read_register(0x40001000)
        fb.write_register(0x40001000, 0xFF)

        log = fb.get_access_log()
        assert len(log) == 2
        assert log[0].is_write is False
        assert log[1].is_write is True
        assert log[1].value == 0xFF

    def test_different_addresses_independent(self, fb: MMIOFallbackModel) -> None:
        """Each address maintains independent state."""
        fb.write_register(0x40001000, 0xAA)
        fb.write_register(0x40002000, 0xBB)
        assert fb.read_register(0x40001000) == 0xAA
        assert fb.read_register(0x40002000) == 0xBB


# ---------------------------------------------------------------------------
# 2. TestCortexMSystemRegisters
# ---------------------------------------------------------------------------

class TestCortexMSystemRegisters:
    @pytest.fixture
    def sys_regs(self) -> CortexMSystemRegisters:
        return CortexMSystemRegisters()

    def test_systick_cvr_decrements_on_read(self, sys_regs: CortexMSystemRegisters) -> None:
        """SysTick CVR (0xE000E018) decrements each read to simulate countdown."""
        val1 = sys_regs.read_register(0xE000E018)
        val2 = sys_regs.read_register(0xE000E018)
        # Each read decrements by 1
        assert val2 == val1 - 1

    def test_scb_cpuid_returns_cortex_m4(self, sys_regs: CortexMSystemRegisters) -> None:
        """SCB CPUID (0xE000ED00) returns Cortex-M4 identifier."""
        assert sys_regs.read_register(0xE000ED00) == 0x410FC241

    def test_nvic_registers_default_zero(self, sys_regs: CortexMSystemRegisters) -> None:
        """NVIC registers not in defaults table should return 0."""
        # NVIC_ISER0 is not in the defaults dict explicitly, should return 0
        assert sys_regs.read_register(0xE000E100) == 0x00000000

    def test_write_then_read_writable_register(self, sys_regs: CortexMSystemRegisters) -> None:
        """Writing to a system register and reading it back returns the written value."""
        # Write to ICSR
        sys_regs.write_register(0xE000ED04, 0x12345678)
        assert sys_regs.read_register(0xE000ED04) == 0x12345678

    def test_contains_ppb_region(self, sys_regs: CortexMSystemRegisters) -> None:
        """PPB addresses (0xE0000000-0xE00FFFFF) are contained."""
        assert sys_regs.contains(0xE0000000) is True
        assert sys_regs.contains(0xE000E018) is True
        assert sys_regs.contains(0xE00FFFFF) is True

    def test_not_contains_outside_ppb(self, sys_regs: CortexMSystemRegisters) -> None:
        assert sys_regs.contains(0x40000000) is False
        assert sys_regs.contains(0xE0100000) is False

    def test_systick_csr_default(self, sys_regs: CortexMSystemRegisters) -> None:
        assert sys_regs.read_register(0xE000E010) == 0x00000004

    def test_fpu_cpacr_default(self, sys_regs: CortexMSystemRegisters) -> None:
        """CPACR default enables CP10+CP11 full access."""
        assert sys_regs.read_register(0xE000ED88) == 0x00F00000

    def test_nvic_ispr_write_tracked(self, sys_regs: CortexMSystemRegisters) -> None:
        """Writing to NVIC_ISPR is accepted and stored."""
        sys_regs.write_register(0xE000E200, 0x00000004)
        assert sys_regs.read_register(0xE000E200) == 0x00000004


# ---------------------------------------------------------------------------
# 3. TestCompositeMMIOHandler
# ---------------------------------------------------------------------------

class TestCompositeMMIOHandler:
    def _make_svd_model(
        self,
        name: str = "USART1",
        base: int = 0x40011000,
    ) -> SVDPeripheralModel:
        """Create a minimal SVD peripheral model for testing."""
        periph = SVDPeripheral(
            name=name,
            base_address=base,
            registers=[
                SVDRegister(name="SR", offset=0x00, reset_value=0x000000C0),
                SVDRegister(name="DR", offset=0x04, reset_value=0x00000000),
            ],
        )
        return SVDPeripheralModel(periph)

    def test_svd_model_takes_priority(self) -> None:
        """Address within SVD peripheral range is handled by SVD model."""
        model = self._make_svd_model()
        handler = CompositeMMIOHandler(
            svd_models={"usart1": model},
        )

        # Read at USART1 base (offset 0 = SR register)
        _val = handler.read(0x40011000)
        stats = handler.get_coverage_stats()
        assert stats["svd_handled"] == 1
        assert stats["fallback_handled"] == 0

    def test_unknown_address_falls_to_fallback(self) -> None:
        """Address not in any SVD model range goes to fallback."""
        handler = CompositeMMIOHandler(svd_models={})

        _val = handler.read(0x40050000)
        stats = handler.get_coverage_stats()
        assert stats["fallback_handled"] == 1
        assert stats["svd_handled"] == 0

    def test_system_registers_handled_by_system_handler(self) -> None:
        """PPB region addresses go to the system register handler."""
        handler = CompositeMMIOHandler()

        val = handler.read(0xE000ED00)  # SCB CPUID
        assert val == 0x410FC241
        stats = handler.get_coverage_stats()
        assert stats["system_handled"] == 1

    def test_coverage_stats_tracking(self) -> None:
        """Coverage stats accumulate across reads and writes."""
        model = self._make_svd_model()
        handler = CompositeMMIOHandler(svd_models={"usart1": model})

        handler.read(0x40011000)   # SVD
        handler.read(0xE000ED00)   # system
        handler.read(0x40050000)   # fallback
        handler.write(0x40050000, 0x1)  # fallback

        stats = handler.get_coverage_stats()
        assert stats["svd_handled"] == 1
        assert stats["system_handled"] == 1
        assert stats["fallback_handled"] == 2
        assert stats["total"] == 4

    def test_write_to_svd_model(self) -> None:
        """Write within SVD peripheral range is routed to SVD model."""
        model = self._make_svd_model()
        handler = CompositeMMIOHandler(svd_models={"usart1": model})

        handler.write(0x40011004, 0x41)  # Write to DR register
        stats = handler.get_coverage_stats()
        assert stats["svd_handled"] == 1

    def test_write_to_system_register(self) -> None:
        """Write to system register range is handled correctly."""
        handler = CompositeMMIOHandler()

        handler.write(0xE000ED04, 0x12345678)
        assert handler.read(0xE000ED04) == 0x12345678
        stats = handler.get_coverage_stats()
        assert stats["system_handled"] == 2  # one write + one read

    def test_fallback_property(self) -> None:
        """Can access the underlying fallback model for diagnostics."""
        handler = CompositeMMIOHandler()
        assert isinstance(handler.fallback, MMIOFallbackModel)

    def test_system_regs_property(self) -> None:
        handler = CompositeMMIOHandler()
        assert isinstance(handler.system_regs, CortexMSystemRegisters)

    def test_svd_coverage_pct(self) -> None:
        model = self._make_svd_model()
        handler = CompositeMMIOHandler(svd_models={"usart1": model})

        handler.read(0x40011000)  # SVD
        handler.read(0x40050000)  # fallback

        stats = handler.get_coverage_stats()
        assert stats["svd_coverage_pct"] == 50.0
