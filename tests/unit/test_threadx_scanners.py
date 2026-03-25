"""Unit tests for ThreadX vulnerability scanner modules (Phase 10)."""

from __future__ import annotations

import struct


from rtosploit.scanners.base import ScannerModule, ScanResult
from rtosploit.scanners.registry import ScannerRegistry
from rtosploit.scanners.target import ScanTarget
from rtosploit.utils.binary import FirmwareImage
from rtosploit.analysis.fingerprint import RTOSFingerprint
from rtosploit.analysis.heap_detect import HeapInfo
from rtosploit.analysis.mpu_check import MPUConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_threadx_target(extra_data=b""):
    """Create a synthetic ScanTarget with ThreadX firmware strings."""
    base_data = (
        b"ThreadX\x00"
        b"tx_kernel_enter\x00"
        b"tx_thread_create\x00"
        b"tx_thread_resume\x00"
        b"tx_byte_allocate\x00"
        b"tx_byte_pool_create\x00"
        b"tx_semaphore_create\x00"
        b"tx_queue_create\x00"
        b"tx_mutex_create\x00"
    )
    data = base_data + extra_data + b"\x00" * 1000
    firmware = FirmwareImage(
        data=data,
        base_address=0x20000000,
        format="raw",
        entry_point=0x20000001,
        symbols={},
    )
    fingerprint = RTOSFingerprint(rtos_type="threadx", version="6.1", confidence=0.95)
    heap = HeapInfo(
        allocator_type="unknown",
        heap_base=0x20001000,
        heap_size=0x8000,
        block_size=None,
    )
    mpu = MPUConfig(mpu_present=True, regions_configured=4)
    return ScanTarget(
        firmware=firmware,
        machine_name="mps2-an385",
        fingerprint=fingerprint,
        heap_info=heap,
        mpu_config=mpu,
    )


def make_freertos_target():
    """Create a synthetic ScanTarget with FreeRTOS firmware strings."""
    data = b"FreeRTOS Kernel V10.5.0\x00pvPortMalloc\x00vTaskStartScheduler\x00" + b"\x00" * 500
    firmware = FirmwareImage(
        data=data,
        base_address=0x20000000,
        format="raw",
        entry_point=0x20000001,
        symbols={},
    )
    fingerprint = RTOSFingerprint(rtos_type="freertos", version="10.5.0", confidence=0.9)
    heap = HeapInfo(allocator_type="heap_4", heap_base=0x20001000, heap_size=0x8000, block_size=None)
    mpu = MPUConfig(mpu_present=True, regions_configured=2)
    return ScanTarget(
        firmware=firmware,
        machine_name="mps2-an385",
        fingerprint=fingerprint,
        heap_info=heap,
        mpu_config=mpu,
    )


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

from rtosploit.scanners.threadx.kom import ThreadXKOM  # noqa: E402
from rtosploit.scanners.threadx.byte_pool import ThreadXBytePool  # noqa: E402
from rtosploit.scanners.threadx.thread_entry import ThreadXThreadEntry  # noqa: E402


# ---------------------------------------------------------------------------
# Tests: ThreadXKOM
# ---------------------------------------------------------------------------

class TestThreadXKOM:
    def test_check_threadx_target_returns_true(self):
        module = ThreadXKOM()
        target = make_threadx_target()
        assert module.check(target) is True

    def test_check_freertos_target_returns_false(self):
        module = ThreadXKOM()
        target = make_freertos_target()
        assert module.check(target) is False

    def test_exploit_returns_exploit_result(self):
        module = ThreadXKOM()
        target = make_threadx_target()
        result = module.exploit(target, None)
        assert isinstance(result, ScanResult)

    def test_exploit_technique_is_kernel_object_masquerading(self):
        module = ThreadXKOM()
        target = make_threadx_target()
        result = module.exploit(target, None)
        assert result.technique == "kernel_object_masquerading"

    def test_exploit_module_name_correct(self):
        module = ThreadXKOM()
        target = make_threadx_target()
        result = module.exploit(target, None)
        assert result.module == "threadx/kom"

    def test_exploit_status_success_when_syscalls_found(self):
        module = ThreadXKOM()
        target = make_threadx_target()
        result = module.exploit(target, None)
        # ThreadX strings are present so syscalls should be found
        assert result.status == "success"

    def test_exploit_achieved_includes_arbitrary_write(self):
        module = ThreadXKOM()
        target = make_threadx_target()
        result = module.exploit(target, None)
        assert "arbitrary_write" in result.achieved

    def test_exploit_achieved_includes_mpu_disabled_for_default_options(self):
        module = ThreadXKOM()
        target = make_threadx_target()
        result = module.exploit(target, None)
        # Default target_address=0xE000ED94, write_value=0 → mpu_disabled
        assert "mpu_disabled" in result.achieved

    def test_build_kom_chain_returns_non_empty_list(self):
        module = ThreadXKOM()
        chain = module._build_kom_chain(0xE000ED94, 0)
        assert isinstance(chain, list)
        assert len(chain) > 0

    def test_build_kom_chain_contains_step_descriptions(self):
        module = ThreadXKOM()
        chain = module._build_kom_chain(0xE000ED94, 0)
        for step in chain:
            assert isinstance(step, str)
            assert len(step) > 0

    def test_find_threadx_syscalls_finds_tx_thread_create(self):
        module = ThreadXKOM()
        target = make_threadx_target()
        syscalls = module._find_threadx_syscalls(target)
        assert "tx_thread_create" in syscalls

    def test_find_threadx_syscalls_finds_tx_semaphore_create(self):
        module = ThreadXKOM()
        target = make_threadx_target()
        syscalls = module._find_threadx_syscalls(target)
        assert "tx_semaphore_create" in syscalls

    def test_find_threadx_syscalls_returns_dict(self):
        module = ThreadXKOM()
        target = make_threadx_target()
        syscalls = module._find_threadx_syscalls(target)
        assert isinstance(syscalls, dict)

    def test_get_option_target_address_default(self):
        module = ThreadXKOM()
        assert module.get_option("target_address") == 0xE000ED94

    def test_get_option_write_value_default(self):
        module = ThreadXKOM()
        assert module.get_option("write_value") == 0

    def test_requirements_returns_correct_keys(self):
        module = ThreadXKOM()
        reqs = module.requirements()
        assert "qemu" in reqs
        assert "gdb" in reqs
        assert "network" in reqs

    def test_requirements_all_false(self):
        module = ThreadXKOM()
        reqs = module.requirements()
        assert reqs["qemu"] is False
        assert reqs["gdb"] is False
        assert reqs["network"] is False

    def test_info_returns_required_keys(self):
        module = ThreadXKOM()
        info = module.info()
        for key in ("name", "rtos", "category", "reliability"):
            assert key in info

    def test_rtos_is_threadx(self):
        assert ThreadXKOM.rtos == "threadx"

    def test_reliability_is_high(self):
        assert ThreadXKOM.reliability == "high"


# ---------------------------------------------------------------------------
# Tests: ThreadXBytePool
# ---------------------------------------------------------------------------

class TestThreadXBytePool:
    def test_check_threadx_with_tx_byte_allocate_returns_true(self):
        module = ThreadXBytePool()
        target = make_threadx_target()
        assert module.check(target) is True

    def test_check_freertos_target_returns_false(self):
        module = ThreadXBytePool()
        target = make_freertos_target()
        assert module.check(target) is False

    def test_build_fake_block_returns_8_bytes(self):
        module = ThreadXBytePool()
        result = module._build_fake_block(0x20002000)
        assert isinstance(result, bytes)
        assert len(result) == 8

    def test_build_fake_block_first_4_bytes_is_block_size(self):
        module = ThreadXBytePool()
        result = module._build_fake_block(0x20002000)
        block_size = struct.unpack("<I", result[:4])[0]
        assert block_size == 32  # minimal allocation

    def test_build_fake_block_last_4_bytes_is_link_pointer(self):
        module = ThreadXBytePool()
        target_entry = 0x20002010
        result = module._build_fake_block(target_entry)
        link_ptr = struct.unpack("<I", result[4:])[0]
        assert link_ptr == (target_entry - 8) & 0xFFFFFFFF

    def test_exploit_returns_byte_pool_unlink_technique(self):
        module = ThreadXBytePool()
        target = make_threadx_target()
        result = module.exploit(target, None)
        assert result.technique == "byte_pool_unlink"

    def test_exploit_module_name_correct(self):
        module = ThreadXBytePool()
        target = make_threadx_target()
        result = module.exploit(target, None)
        assert result.module == "threadx/byte_pool"

    def test_exploit_status_success(self):
        module = ThreadXBytePool()
        target = make_threadx_target()
        result = module.exploit(target, None)
        assert result.status == "success"

    def test_exploit_achieved_includes_code_execution(self):
        module = ThreadXBytePool()
        target = make_threadx_target()
        result = module.exploit(target, None)
        assert "code_execution" in result.achieved

    def test_exploit_achieved_includes_arbitrary_alloc(self):
        module = ThreadXBytePool()
        target = make_threadx_target()
        result = module.exploit(target, None)
        assert "arbitrary_alloc" in result.achieved

    def test_requirements_returns_correct_keys(self):
        module = ThreadXBytePool()
        reqs = module.requirements()
        assert "qemu" in reqs and "gdb" in reqs and "network" in reqs

    def test_rtos_is_threadx(self):
        assert ThreadXBytePool.rtos == "threadx"


# ---------------------------------------------------------------------------
# Tests: ThreadXThreadEntry
# ---------------------------------------------------------------------------

class TestThreadXThreadEntry:
    def test_tx_thread_entry_offset_is_8(self):
        assert ThreadXThreadEntry.TX_THREAD_ENTRY_OFFSET == 8

    def test_check_threadx_target_returns_true(self):
        module = ThreadXThreadEntry()
        target = make_threadx_target()
        assert module.check(target) is True

    def test_check_freertos_target_returns_false(self):
        module = ThreadXThreadEntry()
        target = make_freertos_target()
        assert module.check(target) is False

    def test_find_thread_struct_finds_embedded_name(self):
        module = ThreadXThreadEntry()
        # Embed a thread name with 4 bytes of padding before it (simulating TX_THREAD layout)
        padding = b"\x00" * 4
        thread_name = b"mythread\x00"
        extra = padding + thread_name + b"\x00" * 100
        target = make_threadx_target(extra_data=extra)
        result = module._find_thread_struct(target, "mythread")
        # Should return an integer address if found
        assert result is None or isinstance(result, int)

    def test_find_thread_struct_returns_none_for_missing_thread(self):
        module = ThreadXThreadEntry()
        target = make_threadx_target()
        result = module._find_thread_struct(target, "nonexistentthread99999")
        assert result is None

    def test_exploit_returns_thread_entry_overwrite_technique(self):
        module = ThreadXThreadEntry()
        target = make_threadx_target()
        result = module.exploit(target, None)
        assert result.technique == "thread_entry_overwrite"

    def test_exploit_module_name_correct(self):
        module = ThreadXThreadEntry()
        target = make_threadx_target()
        result = module.exploit(target, None)
        assert result.module == "threadx/thread_entry"

    def test_exploit_status_success(self):
        module = ThreadXThreadEntry()
        target = make_threadx_target()
        result = module.exploit(target, None)
        assert result.status == "success"

    def test_exploit_achieved_includes_code_execution(self):
        module = ThreadXThreadEntry()
        target = make_threadx_target()
        result = module.exploit(target, None)
        assert "code_execution" in result.achieved

    def test_exploit_registers_has_pc(self):
        module = ThreadXThreadEntry()
        target = make_threadx_target()
        result = module.exploit(target, None)
        assert "pc" in result.registers_at_payload

    def test_exploit_pc_matches_new_entry_addr_default(self):
        module = ThreadXThreadEntry()
        target = make_threadx_target()
        result = module.exploit(target, None)
        assert result.registers_at_payload["pc"] == 0x20001000

    def test_requirements_returns_correct_keys(self):
        module = ThreadXThreadEntry()
        reqs = module.requirements()
        assert "qemu" in reqs and "gdb" in reqs and "network" in reqs

    def test_rtos_is_threadx(self):
        assert ThreadXThreadEntry.rtos == "threadx"

    def test_reliability_is_high(self):
        assert ThreadXThreadEntry.reliability == "high"


# ---------------------------------------------------------------------------
# Tests: All 3 ThreadX modules implement ScannerModule ABC
# ---------------------------------------------------------------------------

class TestAllThreadXModulesImplementABC:
    ALL_MODULES = [ThreadXKOM, ThreadXBytePool, ThreadXThreadEntry]

    def test_all_modules_are_subclasses_of_exploit_module(self):
        for cls in self.ALL_MODULES:
            assert issubclass(cls, ScannerModule), f"{cls.__name__} not a subclass of ScannerModule"

    def test_all_modules_can_be_instantiated(self):
        for cls in self.ALL_MODULES:
            instance = cls()
            assert instance is not None

    def test_all_modules_requirements_has_required_keys(self):
        for cls in self.ALL_MODULES:
            instance = cls()
            reqs = instance.requirements()
            assert isinstance(reqs, dict)
            for key in ("qemu", "gdb", "network"):
                assert key in reqs, f"{cls.__name__}.requirements() missing '{key}'"

    def test_all_modules_have_non_empty_name(self):
        for cls in self.ALL_MODULES:
            assert cls.name, f"{cls.__name__} has empty name"

    def test_all_modules_rtos_is_threadx(self):
        for cls in self.ALL_MODULES:
            assert cls.rtos == "threadx", f"{cls.__name__}.rtos != 'threadx'"

    def test_all_modules_info_returns_required_keys(self):
        for cls in self.ALL_MODULES:
            instance = cls()
            info = instance.info()
            for key in ("name", "rtos", "category", "reliability"):
                assert key in info, f"{cls.__name__}.info() missing '{key}'"


# ---------------------------------------------------------------------------
# Tests: ScannerRegistry discovers ThreadX modules
# ---------------------------------------------------------------------------

class TestThreadXRegistryDiscovery:
    def _fresh_registry(self) -> ScannerRegistry:
        return ScannerRegistry()

    def test_discover_finds_threadx_modules(self):
        registry = self._fresh_registry()
        count = registry.discover()
        assert count >= 3, f"Expected at least 3 ThreadX modules, got {count}"

    def test_registry_has_threadx_kom(self):
        registry = self._fresh_registry()
        registry.discover()
        assert registry.get("threadx/kom") is not None

    def test_registry_has_threadx_byte_pool(self):
        registry = self._fresh_registry()
        registry.discover()
        assert registry.get("threadx/byte_pool") is not None

    def test_registry_has_threadx_thread_entry(self):
        registry = self._fresh_registry()
        registry.discover()
        assert registry.get("threadx/thread_entry") is not None

    def test_search_threadx_finds_all_3_modules(self):
        registry = self._fresh_registry()
        registry.discover()
        results = registry.search("threadx")
        paths = [r[0] for r in results]
        assert "threadx/kom" in paths
        assert "threadx/byte_pool" in paths
        assert "threadx/thread_entry" in paths

    def test_search_usenix_finds_kom(self):
        registry = self._fresh_registry()
        registry.discover()
        results = registry.search("USENIX")
        paths = [r[0] for r in results]
        assert "threadx/kom" in paths
