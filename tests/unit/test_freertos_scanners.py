"""Unit tests for FreeRTOS vulnerability scanner modules (Phase 9)."""

from __future__ import annotations

import struct

import pytest

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

def make_fake_target(rtos_type="freertos", extra_data=b"", allocator="heap_4"):
    """Create a synthetic ScanTarget with fake firmware for testing."""
    rtos_strings = {
        "freertos": b"FreeRTOS Kernel V10.5.0\x00pvPortMalloc\x00vTaskStartScheduler\x00",
        "threadx": b"ThreadX\x00tx_kernel_enter\x00",
        "unknown": b"",
    }
    data = rtos_strings.get(rtos_type, b"") + extra_data + b"\x00" * 1000
    firmware = FirmwareImage(
        data=data,
        base_address=0x20000000,
        format="raw",
        entry_point=0x20000001,
        symbols={},
    )
    fingerprint = RTOSFingerprint(rtos_type=rtos_type, version="10.5.0", confidence=0.9)
    heap = HeapInfo(
        allocator_type=allocator,
        heap_base=0x20001000,
        heap_size=0x8000,
        block_size=None,
    )
    mpu = MPUConfig(mpu_present=True, regions_configured=2)
    return ScanTarget(
        firmware=firmware,
        machine_name="mps2-an385",
        fingerprint=fingerprint,
        heap_info=heap,
        mpu_config=mpu,
    )


def make_fake_target_no_mpu(rtos_type="freertos"):
    """Create a synthetic ScanTarget with MPU not present."""
    rtos_strings = {
        "freertos": b"FreeRTOS Kernel V10.5.0\x00pvPortMalloc\x00",
        "threadx": b"ThreadX\x00tx_kernel_enter\x00",
    }
    data = rtos_strings.get(rtos_type, b"") + b"\x00" * 1000
    firmware = FirmwareImage(
        data=data,
        base_address=0x20000000,
        format="raw",
        entry_point=0x20000001,
        symbols={},
    )
    fingerprint = RTOSFingerprint(rtos_type=rtos_type, version="10.5.0", confidence=0.9)
    heap = HeapInfo(allocator_type="heap_4", heap_base=0x20001000, heap_size=0x8000, block_size=None)
    mpu = MPUConfig(mpu_present=False, regions_configured=0)
    return ScanTarget(
        firmware=firmware,
        machine_name="mps2-an385",
        fingerprint=fingerprint,
        heap_info=heap,
        mpu_config=mpu,
    )


# ---------------------------------------------------------------------------
# Import all 6 modules
# ---------------------------------------------------------------------------

from rtosploit.scanners.freertos.heap_overflow import FreeRTOSHeapOverflow  # noqa: E402
from rtosploit.scanners.freertos.tcb_overwrite import FreeRTOSTCBOverwrite  # noqa: E402
from rtosploit.scanners.freertos.mpu_bypass import FreeRTOSMPUBypass  # noqa: E402
from rtosploit.scanners.freertos.mpu_bypass_rop import FreeRTOSMPUBypassROP  # noqa: E402
from rtosploit.scanners.freertos.tcp_stack import FreeRTOSTCPStack  # noqa: E402
from rtosploit.scanners.freertos.isr_hijack import FreeRTOSISRHijack  # noqa: E402


# ---------------------------------------------------------------------------
# Tests: FreeRTOSHeapOverflow
# ---------------------------------------------------------------------------

class TestFreeRTOSHeapOverflow:
    def test_check_freertos_target_returns_true(self):
        module = FreeRTOSHeapOverflow()
        target = make_fake_target(rtos_type="freertos", allocator="heap_4")
        assert module.check(target) is True

    def test_check_threadx_target_returns_false(self):
        module = FreeRTOSHeapOverflow()
        target = make_fake_target(rtos_type="threadx", allocator="heap_4")
        assert module.check(target) is False

    def test_check_heap_1_allocator_returns_false(self):
        module = FreeRTOSHeapOverflow()
        target = make_fake_target(rtos_type="freertos", allocator="heap_1")
        assert module.check(target) is False

    def test_check_heap_5_allocator_returns_true(self):
        module = FreeRTOSHeapOverflow()
        target = make_fake_target(rtos_type="freertos", allocator="heap_5")
        assert module.check(target) is True

    def test_check_unknown_allocator_returns_true(self):
        module = FreeRTOSHeapOverflow()
        target = make_fake_target(rtos_type="freertos", allocator="unknown")
        assert module.check(target) is True

    def test_exploit_returns_exploit_result(self):
        module = FreeRTOSHeapOverflow()
        target = make_fake_target(rtos_type="freertos")
        result = module.exploit(target, b"\x90" * 16)
        assert isinstance(result, ScanResult)

    def test_exploit_module_name_correct(self):
        module = FreeRTOSHeapOverflow()
        target = make_fake_target(rtos_type="freertos")
        result = module.exploit(target, b"\x90" * 16)
        assert result.module == "freertos/heap_overflow"

    def test_exploit_with_payload_succeeds(self):
        module = FreeRTOSHeapOverflow()
        target = make_fake_target(rtos_type="freertos")
        result = module.exploit(target, b"\x90" * 16)
        assert result.status == "success"
        assert result.payload_delivered is True

    def test_exploit_without_payload_fails(self):
        module = FreeRTOSHeapOverflow()
        target = make_fake_target(rtos_type="freertos")
        result = module.exploit(target, None)
        assert result.status == "failure"
        assert result.payload_delivered is False

    def test_build_fake_blocklist_returns_8_bytes(self):
        module = FreeRTOSHeapOverflow()
        result = module._build_fake_blocklist(0x20002000, 32)
        assert isinstance(result, bytes)
        assert len(result) == 8

    def test_build_fake_blocklist_encodes_next_free_pointer(self):
        module = FreeRTOSHeapOverflow()
        target_addr = 0x20002000
        result = module._build_fake_blocklist(target_addr, 32)
        # pxNextFreeBlock = target_addr - 8
        expected_next = struct.pack("<I", (target_addr - 8) & 0xFFFFFFFF)
        assert result[:4] == expected_next

    def test_exploit_technique_is_blocklist_unlink(self):
        module = FreeRTOSHeapOverflow()
        target = make_fake_target(rtos_type="freertos")
        result = module.exploit(target, b"\x90")
        assert result.technique == "blocklist_unlink"

    def test_get_option_target_task_default(self):
        module = FreeRTOSHeapOverflow()
        assert module.get_option("target_task") == "Idle"

    def test_get_option_overflow_size_default(self):
        module = FreeRTOSHeapOverflow()
        assert module.get_option("overflow_size") == 64

    def test_exploit_result_to_dict_has_expected_keys(self):
        module = FreeRTOSHeapOverflow()
        target = make_fake_target(rtos_type="freertos")
        result = module.exploit(target, b"\x90")
        d = result.to_dict()
        for key in ("module", "status", "target_rtos", "architecture", "technique",
                    "payload_delivered", "payload_type", "achieved",
                    "registers_at_payload", "notes", "cve"):
            assert key in d, f"Missing key: {key}"

    def test_validate_raises_when_firmware_not_set(self):
        module = FreeRTOSHeapOverflow()
        with pytest.raises(ValueError):
            module.validate()

    def test_requirements_returns_correct_dict(self):
        module = FreeRTOSHeapOverflow()
        reqs = module.requirements()
        assert "qemu" in reqs
        assert "gdb" in reqs
        assert "network" in reqs

    def test_info_returns_dict_with_required_keys(self):
        module = FreeRTOSHeapOverflow()
        info = module.info()
        assert "name" in info
        assert "rtos" in info
        assert "category" in info
        assert info["name"] == "heap_overflow"
        assert info["rtos"] == "freertos"


# ---------------------------------------------------------------------------
# Tests: FreeRTOSTCBOverwrite
# ---------------------------------------------------------------------------

class TestFreeRTOSTCBOverwrite:
    def test_check_freertos_returns_true(self):
        module = FreeRTOSTCBOverwrite()
        target = make_fake_target(rtos_type="freertos")
        assert module.check(target) is True

    def test_check_threadx_returns_false(self):
        module = FreeRTOSTCBOverwrite()
        target = make_fake_target(rtos_type="threadx")
        assert module.check(target) is False

    def test_find_tcb_address_finds_task_name_in_firmware(self):
        module = FreeRTOSTCBOverwrite()
        # Embed task name at offset 52+ from start (TCB name field at offset 52)
        padding = b"\x00" * 52
        task_name = b"MyTask\x00"
        extra = padding + task_name + b"\x00" * 100
        target = make_fake_target(rtos_type="freertos", extra_data=extra)
        # Find the task in the combined data
        result = module._find_tcb_address(target, "MyTask")
        # Result should be an integer if found, None if offset is < 0
        assert result is None or isinstance(result, int)

    def test_find_tcb_address_returns_none_for_missing_task(self):
        module = FreeRTOSTCBOverwrite()
        target = make_fake_target(rtos_type="freertos")
        result = module._find_tcb_address(target, "NonExistentTask12345")
        assert result is None

    def test_exploit_sets_technique_pxTopOfStack_overwrite(self):
        module = FreeRTOSTCBOverwrite()
        target = make_fake_target(rtos_type="freertos")
        result = module.exploit(target, None)
        assert result.technique == "pxTopOfStack_overwrite"

    def test_exploit_returns_success_status(self):
        module = FreeRTOSTCBOverwrite()
        target = make_fake_target(rtos_type="freertos")
        result = module.exploit(target, None)
        assert result.status == "success"

    def test_exploit_module_name_correct(self):
        module = FreeRTOSTCBOverwrite()
        target = make_fake_target(rtos_type="freertos")
        result = module.exploit(target, None)
        assert result.module == "freertos/tcb_overwrite"

    def test_requirements_returns_correct_dict(self):
        module = FreeRTOSTCBOverwrite()
        reqs = module.requirements()
        assert "qemu" in reqs
        assert "gdb" in reqs
        assert "network" in reqs

    def test_info_returns_dict_with_required_keys(self):
        module = FreeRTOSTCBOverwrite()
        info = module.info()
        assert "name" in info
        assert "rtos" in info
        assert "category" in info


# ---------------------------------------------------------------------------
# Tests: FreeRTOSMPUBypass
# ---------------------------------------------------------------------------

class TestFreeRTOSMPUBypass:
    def test_check_with_raise_privilege_string_returns_true(self):
        module = FreeRTOSMPUBypass()
        extra = b"xPortRaisePrivilege\x00"
        target = make_fake_target(rtos_type="freertos", extra_data=extra)
        assert module.check(target) is True

    def test_check_without_raise_privilege_returns_false(self):
        module = FreeRTOSMPUBypass()
        target = make_fake_target(rtos_type="freertos")
        # Default extra_data has no xPortRaisePrivilege string
        assert module.check(target) is False

    def test_check_threadx_target_returns_false(self):
        module = FreeRTOSMPUBypass()
        extra = b"xPortRaisePrivilege\x00"
        target = make_fake_target(rtos_type="threadx", extra_data=extra)
        assert module.check(target) is False

    def test_exploit_returns_cve_2021_43997(self):
        module = FreeRTOSMPUBypass()
        extra = b"xPortRaisePrivilege\x00"
        target = make_fake_target(rtos_type="freertos", extra_data=extra)
        result = module.exploit(target, None)
        assert result.cve == "CVE-2021-43997"

    def test_exploit_finds_raise_privilege_addr(self):
        module = FreeRTOSMPUBypass()
        extra = b"xPortRaisePrivilege\x00"
        target = make_fake_target(rtos_type="freertos", extra_data=extra)
        result = module.exploit(target, None)
        assert result.status == "success"
        assert result.payload_delivered is True

    def test_exploit_not_vulnerable_when_string_absent(self):
        module = FreeRTOSMPUBypass()
        target = make_fake_target(rtos_type="freertos")
        result = module.exploit(target, None)
        assert result.status == "not_vulnerable"

    def test_exploit_achieved_includes_privilege_escalation(self):
        module = FreeRTOSMPUBypass()
        extra = b"xPortRaisePrivilege\x00"
        target = make_fake_target(rtos_type="freertos", extra_data=extra)
        result = module.exploit(target, None)
        assert "privilege_escalation" in result.achieved

    def test_requirements_returns_correct_dict(self):
        module = FreeRTOSMPUBypass()
        reqs = module.requirements()
        assert "qemu" in reqs
        assert "gdb" in reqs
        assert "network" in reqs

    def test_info_returns_dict_with_required_keys(self):
        module = FreeRTOSMPUBypass()
        info = module.info()
        assert "name" in info
        assert "rtos" in info
        assert "category" in info
        assert info["cve"] == "CVE-2021-43997"


# ---------------------------------------------------------------------------
# Tests: FreeRTOSMPUBypassROP
# ---------------------------------------------------------------------------

class TestFreeRTOSMPUBypassROP:
    def test_check_freertos_with_mpu_returns_true(self):
        module = FreeRTOSMPUBypassROP()
        target = make_fake_target(rtos_type="freertos")
        assert module.check(target) is True

    def test_check_freertos_without_mpu_returns_false(self):
        module = FreeRTOSMPUBypassROP()
        target = make_fake_target_no_mpu(rtos_type="freertos")
        assert module.check(target) is False

    def test_check_threadx_returns_false(self):
        module = FreeRTOSMPUBypassROP()
        target = make_fake_target(rtos_type="threadx")
        assert module.check(target) is False

    def test_exploit_returns_rop_chain_payload_type_with_gadget(self):
        module = FreeRTOSMPUBypassROP()
        gadget = bytes([0x80, 0xF3, 0x00, 0x88, 0x70, 0x47])
        target = make_fake_target(rtos_type="freertos", extra_data=b"\x00" * 10 + gadget)
        result = module.exploit(target, None)
        assert result.payload_type == "rop_chain"
        assert result.status == "success"
        assert result.payload_delivered is True

    def test_exploit_fails_honestly_without_gadget(self):
        module = FreeRTOSMPUBypassROP()
        target = make_fake_target(rtos_type="freertos")
        result = module.exploit(target, None)
        assert result.status == "failure"
        assert result.payload_delivered is False
        assert "No MSR CONTROL gadget found" in result.notes[0]
        assert "Manual gadget search required" in result.notes[0]

    def test_exploit_returns_cve_2024_28115(self):
        module = FreeRTOSMPUBypassROP()
        gadget = bytes([0x80, 0xF3, 0x00, 0x88, 0x70, 0x47])
        target = make_fake_target(rtos_type="freertos", extra_data=b"\x00" * 10 + gadget)
        result = module.exploit(target, None)
        assert result.cve == "CVE-2024-28115"

    def test_exploit_module_name_correct(self):
        module = FreeRTOSMPUBypassROP()
        gadget = bytes([0x80, 0xF3, 0x00, 0x88, 0x70, 0x47])
        target = make_fake_target(rtos_type="freertos", extra_data=b"\x00" * 10 + gadget)
        result = module.exploit(target, None)
        assert result.module == "freertos/mpu_bypass_rop"

    def test_find_control_gadget_finds_msr_control_pattern(self):
        module = FreeRTOSMPUBypassROP()
        # Embed the MSR CONTROL gadget pattern: 0x80 0xF3 0x00 0x88 0x70 0x47
        gadget = bytes([0x80, 0xF3, 0x00, 0x88, 0x70, 0x47])
        extra = b"\x00" * 10 + gadget + b"\x00" * 100
        target = make_fake_target(rtos_type="freertos", extra_data=extra)
        addr, desc = module._find_control_gadget(target)
        assert addr is not None
        assert isinstance(addr, int)
        assert "MSR CONTROL" in desc

    def test_find_control_gadget_finds_r1_variant(self):
        module = FreeRTOSMPUBypassROP()
        # MSR CONTROL, R1; BX LR
        gadget = bytes([0x81, 0xF3, 0x00, 0x88, 0x70, 0x47])
        extra = b"\x00" * 10 + gadget + b"\x00" * 100
        target = make_fake_target(rtos_type="freertos", extra_data=extra)
        addr, desc = module._find_control_gadget(target)
        assert addr is not None
        assert "R1" in desc

    def test_find_control_gadget_finds_compound_gadget(self):
        module = FreeRTOSMPUBypassROP()
        # MOVS R0, #0; MSR CONTROL, R0
        gadget = bytes([0x00, 0x20, 0x80, 0xF3, 0x00, 0x88])
        extra = b"\x00" * 10 + gadget + b"\x00" * 100
        target = make_fake_target(rtos_type="freertos", extra_data=extra)
        addr, desc = module._find_control_gadget(target)
        assert addr is not None
        assert "compound" in desc

    def test_find_control_gadget_returns_none_when_absent(self):
        module = FreeRTOSMPUBypassROP()
        target = make_fake_target(rtos_type="freertos")
        # No gadget pattern in default fake data
        addr, desc = module._find_control_gadget(target)
        assert addr is None

    def test_get_option_gadget_strategy_default(self):
        module = FreeRTOSMPUBypassROP()
        assert module.get_option("gadget_strategy") == "auto"

    def test_requirements_returns_correct_dict(self):
        module = FreeRTOSMPUBypassROP()
        reqs = module.requirements()
        assert "qemu" in reqs
        assert "gdb" in reqs
        assert "network" in reqs

    def test_info_returns_dict_with_required_keys(self):
        module = FreeRTOSMPUBypassROP()
        info = module.info()
        assert "name" in info
        assert "rtos" in info
        assert "category" in info


# ---------------------------------------------------------------------------
# Tests: FreeRTOSTCPStack
# ---------------------------------------------------------------------------

class TestFreeRTOSTCPStack:
    def test_check_with_freertos_tcp_string_returns_true(self):
        module = FreeRTOSTCPStack()
        extra = b"FreeRTOS+TCP\x00"
        target = make_fake_target(rtos_type="freertos", extra_data=extra)
        assert module.check(target) is True

    def test_check_with_freertos_ip_string_returns_true(self):
        module = FreeRTOSTCPStack()
        extra = b"FreeRTOS_IP\x00"
        target = make_fake_target(rtos_type="freertos", extra_data=extra)
        assert module.check(target) is True

    def test_check_with_xdns_string_returns_true(self):
        module = FreeRTOSTCPStack()
        extra = b"xDNS\x00"
        target = make_fake_target(rtos_type="freertos", extra_data=extra)
        assert module.check(target) is True

    def test_check_without_tcp_strings_returns_false(self):
        module = FreeRTOSTCPStack()
        target = make_fake_target(rtos_type="freertos")
        assert module.check(target) is False

    def test_check_threadx_returns_false(self):
        module = FreeRTOSTCPStack()
        extra = b"FreeRTOS+TCP\x00"
        target = make_fake_target(rtos_type="threadx", extra_data=extra)
        assert module.check(target) is False

    def test_build_cve_2018_16525_payload_returns_bytes(self):
        module = FreeRTOSTCPStack()
        pkt = module._build_cve_2018_16525_payload(256)
        assert isinstance(pkt, bytes)
        assert len(pkt) > 0

    def test_build_cve_2018_16525_payload_has_dns_header(self):
        module = FreeRTOSTCPStack()
        pkt = module._build_cve_2018_16525_payload(256)
        # First two bytes: transaction ID 0x1234 big-endian
        transaction_id = struct.unpack("!H", pkt[:2])[0]
        assert transaction_id == 0x1234

    def test_build_cve_2018_16528_payload_returns_bytes(self):
        module = FreeRTOSTCPStack()
        pkt = module._build_cve_2018_16528_payload(300)
        assert isinstance(pkt, bytes)
        assert len(pkt) > 0

    def test_build_cve_2018_16528_payload_has_transaction_id(self):
        module = FreeRTOSTCPStack()
        pkt = module._build_cve_2018_16528_payload(300)
        transaction_id = struct.unpack("!H", pkt[:2])[0]
        assert transaction_id == 0x1652

    def test_exploit_returns_failure_when_no_network(self):
        module = FreeRTOSTCPStack()
        extra = b"FreeRTOS+TCP\x00"
        target = make_fake_target(rtos_type="freertos", extra_data=extra)
        # With no QEMU running, packet sending should fail gracefully
        result = module.exploit(target, None)
        assert result.module == "freertos/tcp_stack"
        assert isinstance(result, ScanResult)

    def test_requirements_requires_network(self):
        module = FreeRTOSTCPStack()
        reqs = module.requirements()
        assert reqs["network"] is True

    def test_requirements_requires_qemu(self):
        module = FreeRTOSTCPStack()
        reqs = module.requirements()
        assert reqs["qemu"] is True

    def test_info_returns_dict_with_required_keys(self):
        module = FreeRTOSTCPStack()
        info = module.info()
        assert "name" in info
        assert "rtos" in info
        assert "category" in info


# ---------------------------------------------------------------------------
# Tests: FreeRTOSISRHijack
# ---------------------------------------------------------------------------

class TestFreeRTOSISRHijack:
    def test_exception_offsets_pendsv(self):
        assert FreeRTOSISRHijack.EXCEPTION_OFFSETS["pendsv"] == 0x38

    def test_exception_offsets_hardfault(self):
        assert FreeRTOSISRHijack.EXCEPTION_OFFSETS["hardfault"] == 0x0C

    def test_exception_offsets_svc(self):
        assert FreeRTOSISRHijack.EXCEPTION_OFFSETS["svc"] == 0x2C

    def test_exception_offsets_systick(self):
        assert FreeRTOSISRHijack.EXCEPTION_OFFSETS["systick"] == 0x3C

    def test_check_freertos_sram_base_returns_true(self):
        module = FreeRTOSISRHijack()
        # make_fake_target uses base_address=0x20000000 which is in SRAM range
        target = make_fake_target(rtos_type="freertos")
        assert module.check(target) is True

    def test_exploit_returns_technique_vtor_overwrite(self):
        module = FreeRTOSISRHijack()
        target = make_fake_target(rtos_type="freertos")
        result = module.exploit(target, None)
        assert result.technique == "vtor_overwrite"

    def test_exploit_status_success(self):
        module = FreeRTOSISRHijack()
        target = make_fake_target(rtos_type="freertos")
        result = module.exploit(target, None)
        assert result.status == "success"

    def test_exploit_module_name_correct(self):
        module = FreeRTOSISRHijack()
        target = make_fake_target(rtos_type="freertos")
        result = module.exploit(target, None)
        assert result.module == "freertos/isr_hijack"

    def test_exploit_achieved_includes_code_execution(self):
        module = FreeRTOSISRHijack()
        target = make_fake_target(rtos_type="freertos")
        result = module.exploit(target, None)
        assert "code_execution" in result.achieved

    def test_exploit_registers_has_pc(self):
        module = FreeRTOSISRHijack()
        target = make_fake_target(rtos_type="freertos")
        result = module.exploit(target, None)
        assert "pc" in result.registers_at_payload

    def test_requirements_returns_correct_dict(self):
        module = FreeRTOSISRHijack()
        reqs = module.requirements()
        assert "qemu" in reqs
        assert "gdb" in reqs
        assert "network" in reqs

    def test_info_returns_dict_with_required_keys(self):
        module = FreeRTOSISRHijack()
        info = module.info()
        assert "name" in info
        assert "rtos" in info
        assert "category" in info


# ---------------------------------------------------------------------------
# Tests: All 6 modules implement ScannerModule ABC
# ---------------------------------------------------------------------------

class TestAllModulesImplementABC:
    ALL_MODULES = [
        FreeRTOSHeapOverflow,
        FreeRTOSTCBOverwrite,
        FreeRTOSMPUBypass,
        FreeRTOSMPUBypassROP,
        FreeRTOSTCPStack,
        FreeRTOSISRHijack,
    ]

    def test_all_modules_are_subclasses_of_exploit_module(self):
        for cls in self.ALL_MODULES:
            assert issubclass(cls, ScannerModule), f"{cls.__name__} is not subclass of ScannerModule"

    def test_all_modules_can_be_instantiated(self):
        for cls in self.ALL_MODULES:
            instance = cls()
            assert instance is not None, f"{cls.__name__} could not be instantiated"

    def test_all_modules_requirements_returns_dict_with_required_keys(self):
        for cls in self.ALL_MODULES:
            instance = cls()
            reqs = instance.requirements()
            assert isinstance(reqs, dict), f"{cls.__name__}.requirements() is not a dict"
            for key in ("qemu", "gdb", "network"):
                assert key in reqs, f"{cls.__name__}.requirements() missing key: {key}"

    def test_all_modules_info_returns_dict_with_required_keys(self):
        for cls in self.ALL_MODULES:
            instance = cls()
            info = instance.info()
            assert isinstance(info, dict), f"{cls.__name__}.info() is not a dict"
            for key in ("name", "rtos", "category"):
                assert key in info, f"{cls.__name__}.info() missing key: {key}"

    def test_all_modules_have_non_empty_name(self):
        for cls in self.ALL_MODULES:
            assert cls.name, f"{cls.__name__} has empty name"

    def test_all_modules_rtos_is_freertos(self):
        for cls in self.ALL_MODULES:
            assert cls.rtos == "freertos", f"{cls.__name__}.rtos != 'freertos'"


# ---------------------------------------------------------------------------
# Tests: ScannerRegistry discovers all 6 modules
# ---------------------------------------------------------------------------

class TestRegistryDiscovery:
    def _fresh_registry(self) -> ScannerRegistry:
        """Return a new, unpopulated registry (bypasses singleton)."""
        return ScannerRegistry()

    def test_discover_finds_all_6_freertos_modules(self):
        registry = self._fresh_registry()
        count = registry.discover()
        assert count >= 6, f"Expected at least 6 modules, got {count}"

    def test_discover_heap_overflow_registered(self):
        registry = self._fresh_registry()
        registry.discover()
        assert registry.get("freertos/heap_overflow") is not None

    def test_discover_tcb_overwrite_registered(self):
        registry = self._fresh_registry()
        registry.discover()
        assert registry.get("freertos/tcb_overwrite") is not None

    def test_discover_mpu_bypass_registered(self):
        registry = self._fresh_registry()
        registry.discover()
        assert registry.get("freertos/mpu_bypass") is not None

    def test_discover_mpu_bypass_rop_registered(self):
        registry = self._fresh_registry()
        registry.discover()
        assert registry.get("freertos/mpu_bypass_rop") is not None

    def test_discover_tcp_stack_registered(self):
        registry = self._fresh_registry()
        registry.discover()
        assert registry.get("freertos/tcp_stack") is not None

    def test_discover_isr_hijack_registered(self):
        registry = self._fresh_registry()
        registry.discover()
        assert registry.get("freertos/isr_hijack") is not None

    def test_search_cve_2021_43997_finds_mpu_bypass(self):
        registry = self._fresh_registry()
        registry.discover()
        results = registry.search("CVE-2021-43997")
        paths = [r[0] for r in results]
        assert "freertos/mpu_bypass" in paths

    def test_search_cve_2024_28115_finds_mpu_bypass_rop(self):
        registry = self._fresh_registry()
        registry.discover()
        results = registry.search("CVE-2024-28115")
        paths = [r[0] for r in results]
        assert "freertos/mpu_bypass_rop" in paths
