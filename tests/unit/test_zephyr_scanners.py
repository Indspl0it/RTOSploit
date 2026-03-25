"""Unit tests for Zephyr vulnerability scanner modules (Phase 11)."""

from __future__ import annotations

import struct


from rtosploit.scanners.base import ScannerModule
from rtosploit.scanners.registry import ScannerRegistry
from rtosploit.scanners.target import ScanTarget
from rtosploit.utils.binary import FirmwareImage
from rtosploit.analysis.fingerprint import RTOSFingerprint
from rtosploit.analysis.heap_detect import HeapInfo
from rtosploit.analysis.mpu_check import MPUConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_zephyr_target(extra_data=b"", include_bt=False, include_vrfy=False):
    """Create a synthetic ScanTarget with Zephyr firmware strings."""
    base_data = b"zephyr_version_string\x00k_thread_create\x00z_thread_essential_set\x00"
    if include_bt:
        base_data += b"bt_enable\x00bt_le_scan_start\x00BT_GATT_SERVICE_DEFINE\x00"
    if include_vrfy:
        base_data += (
            b"z_vrfy_k_sem_take\x00"
            b"z_vrfy_k_mutex_lock\x00"
            b"z_vrfy_k_thread_create\x00"
            b"z_vrfy_k_msgq_put\x00"
            b"z_vrfy_k_msgq_get\x00"
            b"z_vrfy_k_socket\x00"
        )
    data = base_data + extra_data + b"\x00" * 1000
    firmware = FirmwareImage(
        data=data,
        base_address=0x00000000,
        format="raw",
        entry_point=0x00000001,
        symbols={},
    )
    fingerprint = RTOSFingerprint(rtos_type="zephyr", version="4.2.0", confidence=0.92)
    heap = HeapInfo(
        allocator_type="unknown",
        heap_base=0x20000000,
        heap_size=0x10000,
        block_size=None,
    )
    mpu = MPUConfig(mpu_present=True, regions_configured=8)
    return ScanTarget(
        firmware=firmware,
        machine_name="mps2-an385",
        fingerprint=fingerprint,
        heap_info=heap,
        mpu_config=mpu,
    )


def make_non_zephyr_target():
    """Create a synthetic ScanTarget that is NOT Zephyr."""
    data = b"FreeRTOS Kernel V10.5.0\x00pvPortMalloc\x00" + b"\x00" * 500
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

from rtosploit.scanners.zephyr.syscall_race import ZephyrSyscallRace  # noqa: E402
from rtosploit.scanners.zephyr.ble_overflow import ZephyrBLEOverflow  # noqa: E402
from rtosploit.scanners.zephyr.userspace_off import ZephyrUserspaceOff  # noqa: E402
from rtosploit.scanners.zephyr.ble_cve_2023_4264 import ZephyrBLECVE20234264  # noqa: E402
from rtosploit.scanners.zephyr.ble_cve_2024_6135 import ZephyrBLECVE20246135  # noqa: E402
from rtosploit.scanners.zephyr.ble_cve_2024_6442 import ZephyrBLECVE20246442  # noqa: E402


# ---------------------------------------------------------------------------
# Tests: ZephyrSyscallRace
# ---------------------------------------------------------------------------

class TestZephyrSyscallRace:
    def test_check_with_z_vrfy_in_firmware_returns_true(self):
        module = ZephyrSyscallRace()
        target = make_zephyr_target(include_vrfy=True)
        assert module.check(target) is True

    def test_check_without_zephyr_strings_returns_false(self):
        module = ZephyrSyscallRace()
        target = make_non_zephyr_target()
        assert module.check(target) is False

    def test_check_zephyr_without_vrfy_returns_false(self):
        module = ZephyrSyscallRace()
        target = make_zephyr_target(include_vrfy=False)
        assert module.check(target) is False

    def test_count_syscall_verifiers_counts_correctly(self):
        module = ZephyrSyscallRace()
        # Include 3 known z_vrfy_ strings
        target = make_zephyr_target(include_vrfy=True)
        count = module._count_syscall_verifiers(target)
        assert count >= 6  # we embedded 6 z_vrfy_ strings

    def test_count_syscall_verifiers_zero_when_none(self):
        module = ZephyrSyscallRace()
        target = make_zephyr_target(include_vrfy=False)
        count = module._count_syscall_verifiers(target)
        assert count == 0

    def test_exploit_returns_cve_ghsa(self):
        module = ZephyrSyscallRace()
        target = make_zephyr_target(include_vrfy=True)
        result = module.exploit(target, None)
        assert result.cve == "GHSA-3r6j-5mp3-75wr"

    def test_exploit_technique_is_syscall_stack_overwrite_race(self):
        module = ZephyrSyscallRace()
        target = make_zephyr_target(include_vrfy=True)
        result = module.exploit(target, None)
        assert result.technique == "syscall_stack_overwrite_race"

    def test_exploit_module_name_correct(self):
        module = ZephyrSyscallRace()
        target = make_zephyr_target(include_vrfy=True)
        result = module.exploit(target, None)
        assert result.module == "zephyr/syscall_race"

    def test_exploit_payload_delivered_is_false(self):
        module = ZephyrSyscallRace()
        target = make_zephyr_target(include_vrfy=True)
        result = module.exploit(target, None)
        assert result.payload_delivered is False

    def test_reliability_is_low(self):
        assert ZephyrSyscallRace.reliability == "low"

    def test_rtos_is_zephyr(self):
        assert ZephyrSyscallRace.rtos == "zephyr"

    def test_requirements_needs_qemu_and_gdb(self):
        module = ZephyrSyscallRace()
        reqs = module.requirements()
        assert reqs["qemu"] is True
        assert reqs["gdb"] is True

    def test_exploit_registers_has_pc(self):
        module = ZephyrSyscallRace()
        target = make_zephyr_target(include_vrfy=True)
        result = module.exploit(target, None)
        assert "pc" in result.registers_at_payload


# ---------------------------------------------------------------------------
# Tests: ZephyrBLEOverflow
# ---------------------------------------------------------------------------

class TestZephyrBLEOverflow:
    def test_check_with_bt_strings_returns_true(self):
        module = ZephyrBLEOverflow()
        target = make_zephyr_target(include_bt=True)
        assert module.check(target) is True

    def test_check_without_bt_strings_returns_false(self):
        module = ZephyrBLEOverflow()
        target = make_zephyr_target(include_bt=False)
        assert module.check(target) is False

    def test_check_non_zephyr_returns_false(self):
        module = ZephyrBLEOverflow()
        target = make_non_zephyr_target()
        assert module.check(target) is False

    def test_build_adv_ext_report_returns_bytes(self):
        module = ZephyrBLEOverflow()
        result = module._build_adv_ext_report(512)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_build_adv_ext_report_starts_with_0x3e(self):
        module = ZephyrBLEOverflow()
        result = module._build_adv_ext_report(512)
        assert result[0] == 0x3E

    def test_build_adv_ext_report_bytes_1_2_encode_length(self):
        module = ZephyrBLEOverflow()
        result = module._build_adv_ext_report(512)
        # bytes 1-2: little-endian 16-bit total payload length
        total_len = struct.unpack("<H", result[1:3])[0]
        assert total_len == len(result) - 3

    def test_build_adv_ext_report_contains_overflow_data(self):
        module = ZephyrBLEOverflow()
        data_size = 300
        result = module._build_adv_ext_report(data_size)
        # Should contain the 0x41 overflow bytes
        assert b"\x41" * 10 in result

    def test_exploit_returns_cve_2024_6259(self):
        module = ZephyrBLEOverflow()
        target = make_zephyr_target(include_bt=True)
        result = module.exploit(target, None)
        assert result.cve == "CVE-2024-6259"

    def test_exploit_technique_is_ble_ext_adv_heap_overflow(self):
        module = ZephyrBLEOverflow()
        target = make_zephyr_target(include_bt=True)
        result = module.exploit(target, None)
        assert result.technique == "ble_ext_adv_heap_overflow"

    def test_exploit_module_name_correct(self):
        module = ZephyrBLEOverflow()
        target = make_zephyr_target(include_bt=True)
        result = module.exploit(target, None)
        assert result.module == "zephyr/ble_overflow"

    def test_exploit_payload_type_is_ble_packet(self):
        module = ZephyrBLEOverflow()
        target = make_zephyr_target(include_bt=True)
        result = module.exploit(target, None)
        assert result.payload_type == "ble_packet"

    def test_requirements_needs_network(self):
        module = ZephyrBLEOverflow()
        reqs = module.requirements()
        assert reqs["network"] is True

    def test_rtos_is_zephyr(self):
        assert ZephyrBLEOverflow.rtos == "zephyr"


# ---------------------------------------------------------------------------
# Tests: ZephyrUserspaceOff
# ---------------------------------------------------------------------------

class TestZephyrUserspaceOff:
    def test_check_zephyr_target_returns_true(self):
        module = ZephyrUserspaceOff()
        target = make_zephyr_target()
        assert module.check(target) is True

    def test_check_non_zephyr_returns_false(self):
        module = ZephyrUserspaceOff()
        target = make_non_zephyr_target()
        assert module.check(target) is False

    def test_exploit_with_vrfy_present_mentions_userspace_y(self):
        module = ZephyrUserspaceOff()
        target = make_zephyr_target(include_vrfy=True)
        result = module.exploit(target, None)
        assert any("CONFIG_USERSPACE=y" in note for note in result.notes)

    def test_exploit_without_vrfy_mentions_userspace_n(self):
        module = ZephyrUserspaceOff()
        target = make_zephyr_target(include_vrfy=False)
        result = module.exploit(target, None)
        assert any("CONFIG_USERSPACE=n" in note for note in result.notes)

    def test_category_is_reconnaissance(self):
        assert ZephyrUserspaceOff.category == "reconnaissance"

    def test_exploit_status_success(self):
        module = ZephyrUserspaceOff()
        target = make_zephyr_target()
        result = module.exploit(target, None)
        assert result.status == "success"

    def test_exploit_achieved_includes_reconnaissance_complete(self):
        module = ZephyrUserspaceOff()
        target = make_zephyr_target()
        result = module.exploit(target, None)
        assert "reconnaissance_complete" in result.achieved

    def test_exploit_payload_delivered_is_false(self):
        module = ZephyrUserspaceOff()
        target = make_zephyr_target()
        result = module.exploit(target, None)
        assert result.payload_delivered is False

    def test_reliability_is_excellent(self):
        assert ZephyrUserspaceOff.reliability == "excellent"

    def test_requirements_all_false(self):
        module = ZephyrUserspaceOff()
        reqs = module.requirements()
        assert reqs["qemu"] is False
        assert reqs["gdb"] is False
        assert reqs["network"] is False

    def test_module_name_is_userspace_off(self):
        assert ZephyrUserspaceOff.name == "userspace_off"


# ---------------------------------------------------------------------------
# Tests: CVE stub modules
# ---------------------------------------------------------------------------

class TestZephyrBLECVE20234264:
    def test_check_zephyr_with_bt_strings_returns_true(self):
        module = ZephyrBLECVE20234264()
        target = make_zephyr_target(include_bt=True)
        assert module.check(target) is True

    def test_check_non_zephyr_returns_false(self):
        module = ZephyrBLECVE20234264()
        target = make_non_zephyr_target()
        assert module.check(target) is False

    def test_exploit_returns_cve_2023_4264(self):
        module = ZephyrBLECVE20234264()
        target = make_zephyr_target(include_bt=True)
        result = module.exploit(target, None)
        assert result.cve == "CVE-2023-4264"

    def test_exploit_technique_is_bt_stack_overflow(self):
        module = ZephyrBLECVE20234264()
        target = make_zephyr_target(include_bt=True)
        result = module.exploit(target, None)
        assert result.technique == "bt_stack_overflow"

    def test_all_abstract_methods_implemented(self):
        module = ZephyrBLECVE20234264()
        _target = make_zephyr_target(include_bt=True)
        assert callable(module.check)
        assert callable(module.exploit)
        assert callable(module.cleanup)
        assert callable(module.requirements)

    def test_requirements_returns_dict(self):
        module = ZephyrBLECVE20234264()
        reqs = module.requirements()
        assert isinstance(reqs, dict)
        for key in ("qemu", "gdb", "network"):
            assert key in reqs


class TestZephyrBLECVE20246135:
    def test_check_zephyr_with_hci_strings_returns_true(self):
        module = ZephyrBLECVE20246135()
        extra = b"hci_driver_register\x00"
        target = make_zephyr_target(extra_data=extra)
        assert module.check(target) is True

    def test_check_non_zephyr_returns_false(self):
        module = ZephyrBLECVE20246135()
        target = make_non_zephyr_target()
        assert module.check(target) is False

    def test_exploit_returns_cve_2024_6135(self):
        module = ZephyrBLECVE20246135()
        target = make_zephyr_target(include_bt=True)
        result = module.exploit(target, None)
        assert result.cve == "CVE-2024-6135"

    def test_exploit_technique_is_bt_classic_bounds_check(self):
        module = ZephyrBLECVE20246135()
        target = make_zephyr_target(include_bt=True)
        result = module.exploit(target, None)
        assert result.technique == "bt_classic_bounds_check"

    def test_cleanup_does_not_raise(self):
        module = ZephyrBLECVE20246135()
        target = make_zephyr_target()
        module.cleanup(target)  # should not raise

    def test_requirements_has_required_keys(self):
        module = ZephyrBLECVE20246135()
        reqs = module.requirements()
        for key in ("qemu", "gdb", "network"):
            assert key in reqs


class TestZephyrBLECVE20246442:
    def test_check_zephyr_with_bt_strings_returns_true(self):
        module = ZephyrBLECVE20246442()
        target = make_zephyr_target(include_bt=True)
        assert module.check(target) is True

    def test_check_non_zephyr_returns_false(self):
        module = ZephyrBLECVE20246442()
        target = make_non_zephyr_target()
        assert module.check(target) is False

    def test_exploit_returns_cve_2024_6442(self):
        module = ZephyrBLECVE20246442()
        target = make_zephyr_target(include_bt=True)
        result = module.exploit(target, None)
        assert result.cve == "CVE-2024-6442"

    def test_exploit_technique_is_ble_ascs_overflow(self):
        module = ZephyrBLECVE20246442()
        target = make_zephyr_target(include_bt=True)
        result = module.exploit(target, None)
        assert result.technique == "ble_ascs_overflow"

    def test_all_abstract_methods_implemented(self):
        module = ZephyrBLECVE20246442()
        assert callable(module.check)
        assert callable(module.exploit)
        assert callable(module.cleanup)
        assert callable(module.requirements)

    def test_cleanup_does_not_raise(self):
        module = ZephyrBLECVE20246442()
        target = make_zephyr_target()
        module.cleanup(target)  # should not raise

    def test_requirements_has_required_keys(self):
        module = ZephyrBLECVE20246442()
        reqs = module.requirements()
        for key in ("qemu", "gdb", "network"):
            assert key in reqs

    def test_rtos_is_zephyr(self):
        assert ZephyrBLECVE20246442.rtos == "zephyr"


# ---------------------------------------------------------------------------
# Tests: All Zephyr modules implement ScannerModule ABC
# ---------------------------------------------------------------------------

class TestAllZephyrModulesImplementABC:
    ALL_MODULES = [
        ZephyrSyscallRace,
        ZephyrBLEOverflow,
        ZephyrUserspaceOff,
        ZephyrBLECVE20234264,
        ZephyrBLECVE20246135,
        ZephyrBLECVE20246442,
    ]

    def test_all_modules_are_subclasses_of_exploit_module(self):
        for cls in self.ALL_MODULES:
            assert issubclass(cls, ScannerModule), f"{cls.__name__} not subclass of ScannerModule"

    def test_all_modules_can_be_instantiated(self):
        for cls in self.ALL_MODULES:
            instance = cls()
            assert instance is not None

    def test_all_modules_rtos_is_zephyr(self):
        for cls in self.ALL_MODULES:
            assert cls.rtos == "zephyr", f"{cls.__name__}.rtos != 'zephyr'"

    def test_all_modules_have_non_empty_name(self):
        for cls in self.ALL_MODULES:
            assert cls.name, f"{cls.__name__} has empty name"


# ---------------------------------------------------------------------------
# Tests: ScannerRegistry discovers Zephyr modules
# ---------------------------------------------------------------------------

class TestZephyrRegistryDiscovery:
    def _fresh_registry(self) -> ScannerRegistry:
        return ScannerRegistry()

    def test_discover_finds_zephyr_modules(self):
        registry = self._fresh_registry()
        count = registry.discover()
        # At least 6 zephyr modules + existing freertos and threadx
        assert count >= 6

    def test_registry_has_zephyr_syscall_race(self):
        registry = self._fresh_registry()
        registry.discover()
        assert registry.get("zephyr/syscall_race") is not None

    def test_registry_has_zephyr_ble_overflow(self):
        registry = self._fresh_registry()
        registry.discover()
        assert registry.get("zephyr/ble_overflow") is not None

    def test_registry_has_zephyr_userspace_off(self):
        registry = self._fresh_registry()
        registry.discover()
        assert registry.get("zephyr/userspace_off") is not None

    def test_search_cve_2024_6259_finds_ble_overflow(self):
        registry = self._fresh_registry()
        registry.discover()
        results = registry.search("CVE-2024-6259")
        paths = [r[0] for r in results]
        assert "zephyr/ble_overflow" in paths

    def test_search_ghsa_finds_syscall_race(self):
        registry = self._fresh_registry()
        registry.discover()
        results = registry.search("GHSA-3r6j-5mp3-75wr")
        paths = [r[0] for r in results]
        assert "zephyr/syscall_race" in paths

    def test_search_cve_2023_4264_finds_ble_cve_stub(self):
        registry = self._fresh_registry()
        registry.discover()
        results = registry.search("CVE-2023-4264")
        paths = [r[0] for r in results]
        assert "zephyr/ble_cve_2023_4264" in paths

    def test_search_cve_2024_6135_finds_ble_cve_stub(self):
        registry = self._fresh_registry()
        registry.discover()
        results = registry.search("CVE-2024-6135")
        paths = [r[0] for r in results]
        assert "zephyr/ble_cve_2024_6135" in paths

    def test_search_cve_2024_6442_finds_ble_cve_stub(self):
        registry = self._fresh_registry()
        registry.discover()
        results = registry.search("CVE-2024-6442")
        paths = [r[0] for r in results]
        assert "zephyr/ble_cve_2024_6442" in paths
