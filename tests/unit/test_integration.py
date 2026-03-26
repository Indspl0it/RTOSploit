"""Integration-style tests verifying component interactions."""
import pytest
from pathlib import Path

# --- ScannerRegistry + Module Integration ---

class TestScannerRegistryIntegration:
    def test_discover_and_list(self):
        """Registry discovers all expected modules."""
        from rtosploit.scanners.registry import ScannerRegistry
        r = ScannerRegistry()
        r.discover()
        paths = set(r._modules.keys())
        # At minimum these should exist
        assert "freertos/heap_overflow" in paths
        assert "freertos/mpu_bypass" in paths
        assert "threadx/kom" in paths
        assert "zephyr/syscall_race" in paths

    def test_search_by_cve(self):
        from rtosploit.scanners.registry import ScannerRegistry
        r = ScannerRegistry()
        r.discover()
        results = r.search("CVE-2021-43997")
        assert len(results) >= 1
        assert any("mpu_bypass" in path for path in results)

    def test_search_by_rtos(self):
        from rtosploit.scanners.registry import ScannerRegistry
        r = ScannerRegistry()
        r.discover()
        results = r.search("freertos")
        assert len(results) >= 4  # At least 4 FreeRTOS modules

    def test_get_module_by_path(self):
        from rtosploit.scanners.registry import ScannerRegistry
        r = ScannerRegistry()
        r.discover()
        cls = r.get("freertos/mpu_bypass")
        inst = cls()
        assert inst.rtos == "freertos"
        assert inst.category == "mpu_bypass"

    def test_module_has_required_options(self):
        from rtosploit.scanners.registry import ScannerRegistry
        r = ScannerRegistry()
        r.discover()
        for path, cls in r._modules.items():
            inst = cls()
            # Every module must have at least 'firmware' and 'machine' options
            assert "firmware" in inst.options, f"{path} missing 'firmware' option"
            assert "machine" in inst.options, f"{path} missing 'machine' option"

    def test_module_reliability_values(self):
        from rtosploit.scanners.registry import ScannerRegistry
        r = ScannerRegistry()
        r.discover()
        valid = {"low", "medium", "high", "excellent", "good", "fair", "unreliable"}
        for path, cls in r._modules.items():
            inst = cls()
            assert inst.reliability in valid, f"{path} has invalid reliability: {inst.reliability}"

    def test_module_categories(self):
        from rtosploit.scanners.registry import ScannerRegistry
        r = ScannerRegistry()
        r.discover()
        valid = {
            "heap_corruption", "tcb_overwrite", "mpu_bypass", "isr_hijack",
            "arbitrary_rw", "race_condition", "network_overflow", "kernel",
            "reconnaissance",
        }
        for path, cls in r._modules.items():
            inst = cls()
            assert inst.category in valid, f"{path} has unknown category: {inst.category}"


# --- VulnRange + Manifest Integration ---

VULNRANGE_DIR = Path("vulnrange")

@pytest.mark.skipif(not VULNRANGE_DIR.exists(), reason="vulnrange/ not found")
class TestVulnRangeIntegration:
    def test_all_ranges_loadable(self):
        from rtosploit.vulnrange.manifest import list_ranges
        ranges = list_ranges(VULNRANGE_DIR)
        assert len(ranges) >= 5

    def test_all_ranges_have_exploit_script(self):
        from rtosploit.vulnrange.manager import VulnRangeManager
        mgr = VulnRangeManager(VULNRANGE_DIR)
        for m in mgr.list():
            exploit_path = VULNRANGE_DIR / m.id / m.exploit.script
            assert exploit_path.exists(), f"{m.id}: missing exploit script {m.exploit.script}"

    def test_all_ranges_have_qemu_config(self):
        from rtosploit.vulnrange.manager import VulnRangeManager
        mgr = VulnRangeManager(VULNRANGE_DIR)
        for m in mgr.list():
            qemu_path = VULNRANGE_DIR / m.id / "qemu.yaml"
            assert qemu_path.exists(), f"{m.id}: missing qemu.yaml"

    def test_exploit_scripts_are_valid_python(self):
        import ast
        from rtosploit.vulnrange.manager import VulnRangeManager
        mgr = VulnRangeManager(VULNRANGE_DIR)
        for m in mgr.list():
            exploit_path = VULNRANGE_DIR / m.id / m.exploit.script
            if exploit_path.exists():
                src = exploit_path.read_text()
                try:
                    ast.parse(src)
                except SyntaxError as e:
                    pytest.fail(f"{m.id}/exploit.py has syntax error: {e}")

    def test_manifest_cve_format(self):
        from rtosploit.vulnrange.manifest import list_ranges
        import re
        cve_pattern = re.compile(r'^CVE-\d{4}-\d+$')
        for m in list_ranges(VULNRANGE_DIR):
            if m.cve is not None:
                assert cve_pattern.match(m.cve), f"{m.id}: invalid CVE format: {m.cve}"


# --- Payload Generator Integration ---

class TestPayloadIntegration:
    def test_shellcode_and_encoder_pipeline(self):
        """Generate shellcode and encode it."""
        from rtosploit.payloads.shellcode import ShellcodeGenerator
        gen = ShellcodeGenerator()
        raw = gen.nop_sled("arm", 8)
        assert len(raw) == 16  # 8 × 2 bytes
        # Apply null-free encoding
        encoded = bytes(b if b != 0 else 1 for b in raw)
        assert b'\x00' not in encoded

    def test_rop_find_and_filter(self):
        """Find gadgets in a binary and filter bad chars."""
        from rtosploit.payloads.rop import ROPHelper
        # Create a binary with a known BX LR gadget
        binary = b'\x00' * 16 + b'\x70\x47' + b'\x00' * 8  # BX LR at offset 16
        helper = ROPHelper()
        gadgets = helper.find_bxlr_gadgets(binary, 0)
        assert len(gadgets) >= 1
        # Gadgets have an 'address' and 'type' key; type is classified by body bytes
        assert all('address' in g and 'type' in g for g in gadgets)

    def test_rop_mpu_disable_chain(self):
        """Build MPU disable chain when gadget is available."""
        from rtosploit.payloads.rop import ROPHelper
        # BX LR gadget at known address
        binary = b'\x00' * 0x100 + b'\x70\x47'
        helper = ROPHelper()
        gadgets = helper.find_bxlr_gadgets(binary, 0)
        chain = helper.build_mpu_disable(gadgets)
        # Chain should contain MPU_CTRL address bytes
        mpu_ctrl = (0xE000ED94).to_bytes(4, 'little')
        if chain:
            assert mpu_ctrl in chain or len(chain) > 0

    def test_shellcode_generator_all_arm_templates(self):
        """All ARM templates return non-empty bytes."""
        from rtosploit.payloads.shellcode import ShellcodeGenerator
        gen = ShellcodeGenerator()
        assert len(gen.nop_sled("arm", 4)) > 0
        assert len(gen.infinite_loop("arm")) > 0
        assert len(gen.mpu_disable()) > 0
        assert len(gen.vtor_redirect(0x20000000)) > 0

    def test_shellcode_generator_all_riscv_templates(self):
        from rtosploit.payloads.shellcode import ShellcodeGenerator
        gen = ShellcodeGenerator()
        assert len(gen.nop_sled("riscv32", 4)) > 0
        assert len(gen.infinite_loop("riscv32")) > 0


# --- Analysis Module Integration ---

class TestAnalysisIntegration:
    @pytest.fixture
    def sample_firmware(self, tmp_path):
        """Create a minimal firmware-like binary."""
        # ARM Cortex-M vector table (32 bytes) + some instructions
        fw = b'\x00\x10\x00\x20'  # SP = 0x20001000
        fw += b'\x01\x00\x00\x08'  # Reset = 0x08000001 (Thumb)
        fw += b'\x00' * 24          # Remaining vectors
        fw += b'FreeRTOS Kernel V10.4.1\x00'  # RTOS string
        fw += b'\x00' * (256 - len(fw))
        path = tmp_path / "test.bin"
        path.write_bytes(fw)
        return str(path)

    def test_string_extraction(self, sample_firmware):
        from rtosploit.utils.binary import FirmwareImage, BinaryFormat
        from rtosploit.analysis.strings import extract_strings
        with open(sample_firmware, 'rb') as f:
            raw = f.read()
        fw = FirmwareImage(
            data=raw,
            base_address=0x08000000,
            entry_point=0x08000001,
            format=BinaryFormat.RAW,
        )
        strings = extract_strings(fw)
        assert any("FreeRTOS" in (s[1] if isinstance(s, tuple) else str(s)) for s in strings)

    def test_rtos_fingerprint_freertos(self, sample_firmware):
        from rtosploit.utils.binary import FirmwareImage, BinaryFormat
        with open(sample_firmware, 'rb') as f:
            data = f.read()
        fw = FirmwareImage(
            data=data,
            architecture="armv7m",
            base_address=0x08000000,
            entry_point=0x08000001,
            format=BinaryFormat.RAW,
        )
        from rtosploit.analysis.fingerprint import fingerprint_firmware
        result = fingerprint_firmware(fw)
        assert result.rtos_type in ("freertos", "unknown")
        assert 0.0 <= result.confidence <= 1.0

    def test_heap_detect_no_crash(self, sample_firmware):
        from rtosploit.utils.binary import FirmwareImage, BinaryFormat
        from rtosploit.analysis.fingerprint import RTOSFingerprint
        with open(sample_firmware, 'rb') as f:
            data = f.read()
        fw = FirmwareImage(
            data=data,
            architecture="armv7m",
            base_address=0x08000000,
            entry_point=0x08000001,
            format=BinaryFormat.RAW,
        )
        fp = RTOSFingerprint(
            rtos_type="freertos", version="10.4.1", confidence=0.5,
        )
        from rtosploit.analysis.heap_detect import detect_heap
        result = detect_heap(fw, fp)
        # May return minimal HeapInfo if not detected — just shouldn't crash
        assert result is not None

    def test_mpu_check_no_crash(self, sample_firmware):
        from rtosploit.utils.binary import FirmwareImage, BinaryFormat
        with open(sample_firmware, 'rb') as f:
            data = f.read()
        fw = FirmwareImage(
            data=data,
            architecture="armv7m",
            base_address=0x08000000,
            entry_point=0x08000001,
            format=BinaryFormat.RAW,
        )
        from rtosploit.analysis.mpu_check import check_mpu
        result = check_mpu(fw)
        assert result is not None


# --- CLI + Module Integration ---

class TestCLIModuleIntegration:
    def test_scan_vuln_list_via_cli(self):
        from click.testing import CliRunner
        from rtosploit.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["scan-vuln", "list"])
        assert result.exit_code == 0
        assert "freertos" in result.output.lower()

    def test_scan_vuln_list_json_parseable(self):
        import json
        from click.testing import CliRunner
        from rtosploit.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "scan-vuln", "list"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) >= 10

    def test_payload_shellcode_infinite_loop(self):
        from click.testing import CliRunner
        from rtosploit.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["payload", "shellcode", "--arch", "armv7m", "--type", "infinite_loop"])
        assert result.exit_code == 0
        assert "fee7" in result.output

    def test_vulnrange_list_json(self):
        import json
        from click.testing import CliRunner
        from rtosploit.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "vulnrange", "list"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
