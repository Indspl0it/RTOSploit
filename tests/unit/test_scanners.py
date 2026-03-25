"""Unit tests for the RTOSploit vulnerability scanner framework core (Phase 8)."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Optional

import pytest

from rtosploit.scanners.base import ScannerModule, ScanOption, ScanResult
from rtosploit.scanners.registry import ScannerRegistry
from rtosploit.scanners.target import ScanTarget


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_fake_firmware_file(content: bytes = None) -> str:
    """Write a minimal raw firmware blob to a temp file and return its path."""
    if content is None:
        content = b"FreeRTOS Kernel V10.5.0\x00" + b"\x00" * 1000
    f = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
    f.write(content)
    f.close()
    return f.name


class FakeScanner(ScannerModule):
    """Minimal concrete scanner module for unit testing."""

    name = "test_exploit"
    description = "A test scanner for unit testing purposes"
    authors = ["test_author"]
    references = ["CVE-TEST-1234", "https://example.com/vuln"]
    rtos = "freertos"
    rtos_versions = ["*"]
    architecture = "armv7m"
    category = "heap_corruption"
    reliability = "excellent"
    cve = "CVE-TEST-1234"

    def check(self, target) -> bool:
        return True

    def exploit(self, target, payload: Optional[bytes]) -> ScanResult:
        return ScanResult(
            module=self.name,
            status="success",
            target_rtos="freertos",
            architecture="armv7m",
            technique="heap_corruption",
            payload_delivered=True,
            payload_type="shellcode",
            achieved=["code_execution"],
            registers_at_payload={"pc": 0xDEADBEEF},
            notes=["test run"],
            cve=self.cve,
        )

    def cleanup(self, target) -> None:
        pass

    def requirements(self) -> dict:
        return {"qemu": False, "gdb": False, "network": False}


class AnotherFakeScanner(ScannerModule):
    """A second scanner module for registry search/list tests."""

    name = "stack_smash"
    description = "Stack overflow scanner for ThreadX"
    authors = ["another_author"]
    references = ["CVE-STACK-9999"]
    rtos = "threadx"
    rtos_versions = ["6.x", "7.x"]
    architecture = "armv8m"
    category = "stack_overflow"
    reliability = "good"
    cve = "CVE-STACK-9999"

    def check(self, target) -> bool:
        return False

    def exploit(self, target, payload: Optional[bytes]) -> ScanResult:
        return ScanResult(
            module=self.name,
            status="failure",
            target_rtos="threadx",
            architecture="armv8m",
            technique="stack_overflow",
        )

    def cleanup(self, target) -> None:
        pass

    def requirements(self) -> dict:
        return {"qemu": True, "gdb": True, "network": False}


# ---------------------------------------------------------------------------
# ScanOption tests
# ---------------------------------------------------------------------------

class TestScanOption:
    def test_set_str_type(self):
        opt = ScanOption(name="host", type="str", required=False, default=None, description="")
        opt.set("localhost")
        assert opt.current_value == "localhost"
        assert isinstance(opt.current_value, str)

    def test_set_int_type(self):
        opt = ScanOption(name="port", type="int", required=False, default=None, description="")
        opt.set("4444")
        assert opt.current_value == 4444
        assert isinstance(opt.current_value, int)

    def test_set_int_type_from_int(self):
        opt = ScanOption(name="count", type="int", required=False, default=None, description="")
        opt.set(99)
        assert opt.current_value == 99

    def test_set_bool_type_true_string(self):
        opt = ScanOption(name="verbose", type="bool", required=False, default=None, description="")
        for truthy in ("true", "yes", "1", "True", "YES"):
            opt.set(truthy)
            assert opt.current_value is True

    def test_set_bool_type_false_string(self):
        opt = ScanOption(name="verbose", type="bool", required=False, default=None, description="")
        for falsy in ("false", "no", "0", "False", "NO"):
            opt.set(falsy)
            assert opt.current_value is False

    def test_set_bool_type_from_bool(self):
        opt = ScanOption(name="debug", type="bool", required=False, default=None, description="")
        opt.set(True)
        assert opt.current_value is True
        opt.set(False)
        assert opt.current_value is False

    def test_set_path_type(self):
        opt = ScanOption(name="firmware", type="path", required=True, default=None, description="")
        opt.set("/tmp/firmware.bin")
        assert opt.current_value == Path("/tmp/firmware.bin")
        assert isinstance(opt.current_value, Path)

    def test_value_falls_back_to_default_when_not_set(self):
        opt = ScanOption(name="machine", type="str", required=True, default="mps2-an385", description="")
        # current_value is None by default
        assert opt.current_value is None
        assert opt.value == "mps2-an385"

    def test_value_returns_current_over_default(self):
        opt = ScanOption(name="machine", type="str", required=True, default="mps2-an385", description="")
        opt.set("lm3s811evb")
        assert opt.value == "lm3s811evb"


# ---------------------------------------------------------------------------
# ScannerModule tests
# ---------------------------------------------------------------------------

class TestScannerModule:
    def test_concrete_subclass_can_be_instantiated(self):
        module = FakeScanner()
        assert module is not None
        assert module.name == "test_exploit"

    def test_common_options_registered(self):
        module = FakeScanner()
        assert "firmware" in module.options
        assert "machine" in module.options
        assert "payload" in module.options

    def test_common_options_firmware_is_required(self):
        module = FakeScanner()
        assert module.options["firmware"].required is True

    def test_common_options_machine_has_default(self):
        module = FakeScanner()
        assert module.get_option("machine") == "mps2-an385"

    def test_set_option_known_name(self):
        module = FakeScanner()
        module.set_option("machine", "lm3s811evb")
        assert module.get_option("machine") == "lm3s811evb"

    def test_set_option_unknown_name_raises(self):
        module = FakeScanner()
        with pytest.raises(ValueError, match="Unknown option"):
            module.set_option("nonexistent_option", "value")

    def test_get_option_unknown_name_raises(self):
        module = FakeScanner()
        with pytest.raises(ValueError, match="Unknown option"):
            module.get_option("nonexistent_option")

    def test_get_option_returns_default_when_not_set(self):
        module = FakeScanner()
        assert module.get_option("payload") is None  # default is None

    def test_validate_raises_when_required_option_missing(self):
        module = FakeScanner()
        # firmware is required and has no default
        with pytest.raises(ValueError, match="Required option not set"):
            module.validate()

    def test_validate_raises_when_firmware_path_nonexistent(self):
        module = FakeScanner()
        module.set_option("firmware", "/nonexistent/path/to/firmware.bin")
        with pytest.raises(ValueError, match="Firmware file not found"):
            module.validate()

    def test_validate_passes_with_existing_firmware(self):
        path = make_fake_firmware_file()
        try:
            module = FakeScanner()
            module.set_option("firmware", path)
            module.validate()  # should not raise
        finally:
            os.unlink(path)

    def test_info_returns_metadata_dict(self):
        module = FakeScanner()
        info = module.info()
        assert info["name"] == "test_exploit"
        assert info["rtos"] == "freertos"
        assert info["category"] == "heap_corruption"
        assert info["cve"] == "CVE-TEST-1234"


# ---------------------------------------------------------------------------
# ScanResult tests
# ---------------------------------------------------------------------------

class TestScanResult:
    def test_to_dict_contains_required_keys(self):
        result = ScanResult(
            module="freertos/test_exploit",
            status="success",
            target_rtos="freertos",
            architecture="armv7m",
            technique="heap_corruption",
            payload_delivered=True,
            payload_type="shellcode",
            achieved=["code_execution"],
            registers_at_payload={"pc": 0xDEADBEEF},
            notes=["worked"],
            cve="CVE-TEST-1234",
        )
        d = result.to_dict()
        assert d["module"] == "freertos/test_exploit"
        assert d["status"] == "success"
        assert d["target_rtos"] == "freertos"
        assert d["architecture"] == "armv7m"
        assert d["technique"] == "heap_corruption"
        assert d["payload_delivered"] is True
        assert d["payload_type"] == "shellcode"
        assert d["achieved"] == ["code_execution"]
        assert d["registers_at_payload"] == {"pc": 0xDEADBEEF}
        assert d["notes"] == ["worked"]
        assert d["cve"] == "CVE-TEST-1234"

    def test_to_dict_defaults(self):
        result = ScanResult(
            module="m",
            status="not_vulnerable",
            target_rtos="unknown",
            architecture="unknown",
            technique="heap_corruption",
        )
        d = result.to_dict()
        assert d["payload_delivered"] is False
        assert d["payload_type"] is None
        assert d["achieved"] == []
        assert d["registers_at_payload"] == {}
        assert d["notes"] == []
        assert d["cve"] is None


# ---------------------------------------------------------------------------
# ScannerRegistry tests
# ---------------------------------------------------------------------------

class TestScannerRegistry:
    """Tests for ScannerRegistry (using a fresh instance, not the singleton)."""

    def _fresh_registry(self) -> ScannerRegistry:
        """Return a new, unpopulated registry (bypasses singleton)."""
        return ScannerRegistry()

    def test_register_stores_module_by_rtos_name_path(self):
        registry = self._fresh_registry()
        registry.register(FakeScanner)
        assert registry.get("freertos/test_exploit") is FakeScanner

    def test_register_module_without_rtos_uses_name_only(self):
        registry = self._fresh_registry()

        class NoRtosExploit(ScannerModule):
            name = "generic_module"
            description = ""
            authors = []
            references = []
            rtos = ""
            rtos_versions = []
            architecture = "*"
            category = "stack_overflow"
            reliability = "fair"
            cve = None

            def check(self, target): return True
            def exploit(self, target, payload): pass
            def cleanup(self, target): pass
            def requirements(self): return {}

        registry.register(NoRtosExploit)
        assert registry.get("generic_module") is NoRtosExploit

    def test_get_returns_none_for_unknown_path(self):
        registry = self._fresh_registry()
        assert registry.get("freertos/nonexistent") is None

    def test_list_all_returns_sorted_tuples(self):
        registry = self._fresh_registry()
        registry.register(AnotherFakeScanner)
        registry.register(FakeScanner)
        entries = registry.list_all()
        # Should be sorted by path
        paths = [e[0] for e in entries]
        assert paths == sorted(paths)

    def test_list_all_tuple_structure(self):
        registry = self._fresh_registry()
        registry.register(FakeScanner)
        entries = registry.list_all()
        assert len(entries) == 1
        path, name, rtos, category, reliability = entries[0]
        assert path == "freertos/test_exploit"
        assert name == "test_exploit"
        assert rtos == "freertos"
        assert category == "heap_corruption"
        assert reliability == "excellent"

    def test_search_finds_module_by_cve(self):
        registry = self._fresh_registry()
        registry.register(FakeScanner)
        results = registry.search("CVE-TEST-1234")
        assert len(results) == 1
        assert results[0][0] == "freertos/test_exploit"

    def test_search_finds_module_by_category(self):
        registry = self._fresh_registry()
        registry.register(FakeScanner)
        registry.register(AnotherFakeScanner)
        results = registry.search("stack_overflow")
        assert any(r[0] == "threadx/stack_smash" for r in results)
        assert all(r[0] != "freertos/test_exploit" for r in results)

    def test_search_finds_module_by_rtos(self):
        registry = self._fresh_registry()
        registry.register(FakeScanner)
        registry.register(AnotherFakeScanner)
        results = registry.search("freertos")
        assert len(results) == 1
        assert results[0][0] == "freertos/test_exploit"

    def test_search_returns_empty_list_for_no_match(self):
        registry = self._fresh_registry()
        registry.register(FakeScanner)
        results = registry.search("xyzzy_no_such_thing")
        assert results == []

    def test_discover_runs_without_error_on_empty_subdirs(self):
        # The freertos/threadx/zephyr dirs exist but only have __init__.py
        registry = self._fresh_registry()
        count = registry.discover()
        # Count may be 0 if no actual exploit .py files exist yet
        assert isinstance(count, int)
        assert count >= 0


# ---------------------------------------------------------------------------
# ScanTarget tests
# ---------------------------------------------------------------------------

class TestScanTarget:
    def test_from_firmware_path_creates_target(self):
        path = make_fake_firmware_file()
        try:
            target = ScanTarget.from_firmware_path(path, "mps2-an385")
            assert target is not None
            assert target.firmware is not None
            assert target.machine_name == "mps2-an385"
        finally:
            os.unlink(path)

    def test_from_firmware_path_fingerprint_populated(self):
        # FreeRTOS marker embedded in firmware
        path = make_fake_firmware_file(b"FreeRTOS Kernel V10.5.0\x00" + b"\x00" * 500)
        try:
            target = ScanTarget.from_firmware_path(path, "mps2-an385")
            assert target.fingerprint is not None
        finally:
            os.unlink(path)

    def test_rtos_type_property_returns_fingerprint_rtos(self):
        path = make_fake_firmware_file(b"FreeRTOS Kernel V10.5.0\x00" + b"\x00" * 500)
        try:
            target = ScanTarget.from_firmware_path(path, "mps2-an385")
            # rtos_type comes from fingerprint
            assert target.rtos_type in ("freertos", "unknown")
        finally:
            os.unlink(path)

    def test_rtos_type_returns_unknown_when_no_fingerprint(self):
        path = make_fake_firmware_file(b"\x00" * 100)
        try:
            firmware_img = __import__("rtosploit.utils.binary", fromlist=["load_firmware"]).load_firmware(path)
            target = ScanTarget(firmware=firmware_img, machine_name="mps2-an385", fingerprint=None)
            assert target.rtos_type == "unknown"
        finally:
            os.unlink(path)

    def test_architecture_property_defaults_to_unknown_for_unrecognized_raw(self):
        path = make_fake_firmware_file()
        try:
            target = ScanTarget.from_firmware_path(path, "mps2-an385")
            assert target.architecture == "unknown"
        finally:
            os.unlink(path)

    def test_close_is_idempotent(self):
        path = make_fake_firmware_file()
        try:
            target = ScanTarget.from_firmware_path(path, "mps2-an385")
            # No QEMU, so close() should be safe to call multiple times
            target.close()
            target.close()  # Should not raise
        finally:
            os.unlink(path)

    def test_context_manager_closes_on_exit(self):
        path = make_fake_firmware_file()
        try:
            with ScanTarget.from_firmware_path(path, "mps2-an385") as target:
                assert target is not None
            # After exit, _qemu should be None (was already None here)
            assert target._qemu is None
        finally:
            os.unlink(path)

    def test_repr_includes_rtos_and_machine(self):
        path = make_fake_firmware_file()
        try:
            target = ScanTarget.from_firmware_path(path, "mps2-an385")
            r = repr(target)
            assert "mps2-an385" in r
        finally:
            os.unlink(path)

    def test_read_memory_without_qemu_raises(self):
        path = make_fake_firmware_file()
        try:
            target = ScanTarget.from_firmware_path(path, "mps2-an385")
            with pytest.raises(RuntimeError, match="No QEMU instance"):
                target.read_memory(0x20000000, 4)
        finally:
            os.unlink(path)

    def test_write_memory_without_qemu_raises(self):
        path = make_fake_firmware_file()
        try:
            target = ScanTarget.from_firmware_path(path, "mps2-an385")
            with pytest.raises(RuntimeError, match="No QEMU instance"):
                target.write_memory(0x20000000, b"\xde\xad\xbe\xef")
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# run_scan integration-level unit test (no QEMU)
# ---------------------------------------------------------------------------

class TestRunScan:
    def test_run_scan_raises_for_unknown_module(self):
        from rtosploit.scanners.runner import run_scan
        with pytest.raises(ValueError, match="Module not found"):
            run_scan(
                module_path="freertos/nonexistent_module_xyz",
                options={},
            )

    def test_run_scan_raises_for_empty_module_path(self):
        from rtosploit.scanners.runner import run_scan
        with pytest.raises(ValueError, match="Module not found"):
            run_scan(module_path="", options={})
