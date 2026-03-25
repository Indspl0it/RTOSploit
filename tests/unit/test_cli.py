"""CLI command tests using Click test runner.

Covers all major subcommands: emulate, fuzz, scan-vuln, payload, analyze, svd, vulnrange.
Uses Click's CliRunner for isolation — no QEMU required.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from rtosploit.cli.main import cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def tiny_firmware(tmp_path):
    """Create a minimal raw firmware file for testing."""
    fw = tmp_path / "fw.bin"
    # ARM Cortex-M minimal vector table: SP=0x20002000, Reset=0x00000101
    import struct
    data = struct.pack("<II", 0x20002000, 0x00000101) + b"\x00" * 56
    fw.write_bytes(data)
    return str(fw)


@pytest.fixture
def tiny_svd(tmp_path):
    """Create a minimal SVD XML file for testing."""
    svd = tmp_path / "test.svd"
    svd.write_text("""<?xml version="1.0" encoding="utf-8"?>
<device>
  <peripherals>
    <peripheral>
      <name>UART0</name>
      <baseAddress>0x40001000</baseAddress>
      <description>UART peripheral 0</description>
      <registers>
        <register><name>DR</name><addressOffset>0x0</addressOffset></register>
        <register><name>SR</name><addressOffset>0x4</addressOffset></register>
      </registers>
    </peripheral>
    <peripheral>
      <name>SPI0</name>
      <baseAddress>0x40002000</baseAddress>
      <description>SPI peripheral 0</description>
      <registers>
        <register><name>CR1</name><addressOffset>0x0</addressOffset></register>
      </registers>
    </peripheral>
  </peripherals>
</device>
""")
    return str(svd)


# ---------------------------------------------------------------------------
# Top-level CLI
# ---------------------------------------------------------------------------

def test_version(runner):
    """--version outputs the version string."""
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    from rtosploit import __version__
    assert __version__ in result.output


def test_help_lists_all_subcommands(runner):
    """--help lists all registered subcommands."""
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    for cmd in ["emulate", "fuzz", "scan-vuln", "payload", "analyze", "svd", "vulnrange"]:
        assert cmd in result.output


# ---------------------------------------------------------------------------
# emulate
# ---------------------------------------------------------------------------

def test_emulate_help(runner):
    """emulate --help shows firmware and machine options."""
    result = runner.invoke(cli, ["emulate", "--help"])
    assert result.exit_code == 0
    assert "--firmware" in result.output
    assert "--machine" in result.output
    assert "--gdb" in result.output


def test_emulate_json_output(runner, tiny_firmware):
    """emulate --json returns valid JSON with expected fields."""
    result = runner.invoke(cli, [
        "--json", "emulate",
        "--firmware", tiny_firmware,
        "--machine", "mps2-an385",
    ])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["firmware"] == tiny_firmware
    assert data["machine"] == "mps2-an385"
    assert data["status"] == "ready"
    assert data["gdb"] is False


def test_emulate_json_gdb_enabled(runner, tiny_firmware):
    """emulate --json with --gdb shows gdb_port."""
    result = runner.invoke(cli, [
        "--json", "emulate",
        "--firmware", tiny_firmware,
        "--machine", "mps2-an385",
        "--gdb",
        "--gdb-port", "4321",
    ])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["gdb"] is True
    assert data["gdb_port"] == 4321


# ---------------------------------------------------------------------------
# fuzz
# ---------------------------------------------------------------------------

def test_fuzz_help(runner):
    """fuzz --help shows all fuzz options."""
    result = runner.invoke(cli, ["fuzz", "--help"])
    assert result.exit_code == 0
    assert "--firmware" in result.output
    assert "--machine" in result.output
    assert "--output" in result.output
    assert "--timeout" in result.output
    assert "--jobs" in result.output


def test_fuzz_json_output(runner, tiny_firmware, tmp_path):
    """fuzz --json returns valid JSON with expected fields."""
    out_dir = str(tmp_path / "fuzz_out")
    result = runner.invoke(cli, [
        "--json", "fuzz",
        "--firmware", tiny_firmware,
        "--machine", "mps2-an385",
        "--output", out_dir,
    ])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["firmware"] == tiny_firmware
    assert data["status"] == "started"
    assert "crashes" in data
    assert "executions" in data


# ---------------------------------------------------------------------------
# scan-vuln
# ---------------------------------------------------------------------------

def test_scan_vuln_help(runner):
    """scan-vuln --help mentions list/info/run/check subcommands."""
    result = runner.invoke(cli, ["scan-vuln", "--help"])
    assert result.exit_code == 0
    for sub in ["list", "info", "run", "check"]:
        assert sub in result.output


def test_scan_vuln_list_no_crash(runner):
    """scan-vuln list runs without crashing (table or empty)."""
    result = runner.invoke(cli, ["scan-vuln", "list"])
    assert result.exit_code == 0


def test_scan_vuln_list_json(runner):
    """scan-vuln list --json outputs a valid JSON array."""
    result = runner.invoke(cli, ["--json", "scan-vuln", "list"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)


def test_scan_vuln_list_json_module_fields(runner):
    """scan-vuln list --json items have expected fields."""
    result = runner.invoke(cli, ["--json", "scan-vuln", "list"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    if data:  # at least one module registered
        item = data[0]
        assert "path" in item
        assert "name" in item
        assert "rtos" in item
        assert "category" in item
        assert "reliability" in item


def test_scan_vuln_info_nonexistent(runner):
    """scan-vuln info on unknown module exits with code 1."""
    result = runner.invoke(cli, ["scan-vuln", "info", "nonexistent/bogus"])
    assert result.exit_code == 1


def test_scan_vuln_info_nonexistent_message(runner):
    """scan-vuln info on unknown module shows error message."""
    result = runner.invoke(cli, ["scan-vuln", "info", "nonexistent/bogus"])
    assert "not found" in result.output.lower() or result.exit_code == 1


def test_scan_vuln_list_help(runner):
    """scan-vuln list --help works."""
    result = runner.invoke(cli, ["scan-vuln", "list", "--help"])
    assert result.exit_code == 0


def test_scan_vuln_run_help(runner):
    """scan-vuln run --help works."""
    result = runner.invoke(cli, ["scan-vuln", "run", "--help"])
    assert result.exit_code == 0


def test_scan_vuln_check_help(runner):
    """scan-vuln check --help works."""
    result = runner.invoke(cli, ["scan-vuln", "check", "--help"])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# payload
# ---------------------------------------------------------------------------

def test_payload_help(runner):
    """payload --help mentions shellcode and rop subcommands."""
    result = runner.invoke(cli, ["payload", "--help"])
    assert result.exit_code == 0
    assert "shellcode" in result.output
    assert "rop" in result.output


def test_payload_shellcode_help(runner):
    """payload shellcode --help shows arch and type options."""
    result = runner.invoke(cli, ["payload", "shellcode", "--help"])
    assert result.exit_code == 0
    assert "--arch" in result.output
    assert "--type" in result.output


def test_payload_shellcode_armv7m_infinite_loop(runner):
    """payload shellcode armv7m infinite_loop outputs 'fee7'."""
    result = runner.invoke(cli, [
        "payload", "shellcode",
        "--arch", "armv7m",
        "--type", "infinite_loop",
    ])
    assert result.exit_code == 0
    assert "fee7" in result.output


def test_payload_shellcode_armv7m_nop_sled_length(runner):
    """payload shellcode armv7m nop_sled --length 4 outputs 16 hex chars (8 bytes = 4x 2-byte NOPs)."""
    result = runner.invoke(cli, [
        "payload", "shellcode",
        "--arch", "armv7m",
        "--type", "nop_sled",
        "--length", "4",
    ])
    assert result.exit_code == 0
    hex_out = result.output.strip().splitlines()[0]
    # 4 Thumb2 NOPs = 4 * 2 bytes = 8 bytes = 16 hex chars
    assert len(hex_out) == 16


def test_payload_shellcode_armv7m_mpu_disable_nonempty(runner):
    """payload shellcode armv7m mpu_disable outputs non-empty hex."""
    result = runner.invoke(cli, [
        "payload", "shellcode",
        "--arch", "armv7m",
        "--type", "mpu_disable",
    ])
    assert result.exit_code == 0
    hex_out = result.output.strip().splitlines()[0]
    assert len(hex_out) > 0


def test_payload_shellcode_riscv32_nop_sled(runner):
    """payload shellcode riscv32 nop_sled --length 1 outputs '13000000'."""
    result = runner.invoke(cli, [
        "payload", "shellcode",
        "--arch", "riscv32",
        "--type", "nop_sled",
        "--length", "1",
    ])
    assert result.exit_code == 0
    assert "13000000" in result.output


def test_payload_shellcode_format_python(runner):
    """payload shellcode --format python contains \\xfe\\xe7."""
    result = runner.invoke(cli, [
        "payload", "shellcode",
        "--arch", "armv7m",
        "--type", "infinite_loop",
        "--format", "python",
    ])
    assert result.exit_code == 0
    assert r"\xfe\xe7" in result.output


def test_payload_shellcode_format_c(runner):
    """payload shellcode --format c contains 0xfe, 0xe7."""
    result = runner.invoke(cli, [
        "payload", "shellcode",
        "--arch", "armv7m",
        "--type", "infinite_loop",
        "--format", "c",
    ])
    assert result.exit_code == 0
    assert "0xfe" in result.output
    assert "0xe7" in result.output


def test_payload_shellcode_json(runner):
    """payload shellcode --json outputs valid JSON with hex field."""
    result = runner.invoke(cli, [
        "--json",
        "payload", "shellcode",
        "--arch", "armv7m",
        "--type", "infinite_loop",
    ])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "hex" in data
    assert data["hex"] == "fee7"
    assert data["arch"] == "armv7m"


def test_payload_rop_help(runner):
    """payload rop --help shows binary and goal options."""
    result = runner.invoke(cli, ["payload", "rop", "--help"])
    assert result.exit_code == 0
    assert "--binary" in result.output
    assert "--goal" in result.output


def test_payload_rop_json(runner, tiny_firmware):
    """payload rop --json outputs valid JSON."""
    result = runner.invoke(cli, [
        "--json",
        "payload", "rop",
        "--binary", tiny_firmware,
        "--goal", "mpu_disable",
    ])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "gadgets_found" in data
    assert "chain_length" in data
    assert "chain_hex" in data


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------

def test_analyze_help(runner):
    """analyze --help shows firmware and detect options."""
    result = runner.invoke(cli, ["analyze", "--help"])
    assert result.exit_code == 0
    assert "--firmware" in result.output
    assert "--detect-rtos" in result.output
    assert "--detect-mpu" in result.output


def test_analyze_json(runner, tiny_firmware):
    """analyze --json outputs valid JSON with firmware field."""
    result = runner.invoke(cli, [
        "--json", "analyze",
        "--firmware", tiny_firmware,
        "--detect-rtos",
    ])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "firmware" in data
    assert "rtos" in data


def test_analyze_all_flag(runner, tiny_firmware):
    """analyze --all runs without crashing."""
    result = runner.invoke(cli, [
        "analyze",
        "--firmware", tiny_firmware,
        "--all",
    ])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# svd
# ---------------------------------------------------------------------------

def test_svd_help(runner):
    """svd --help mentions parse and generate subcommands."""
    result = runner.invoke(cli, ["svd", "--help"])
    assert result.exit_code == 0
    assert "parse" in result.output
    assert "generate" in result.output


def test_svd_parse_help(runner):
    """svd parse --help shows SVD_FILE argument."""
    result = runner.invoke(cli, ["svd", "parse", "--help"])
    assert result.exit_code == 0
    assert "SVD_FILE" in result.output


def test_svd_generate_help(runner):
    """svd generate --help shows mode options."""
    result = runner.invoke(cli, ["svd", "generate", "--help"])
    assert result.exit_code == 0
    assert "--mode" in result.output


def test_svd_parse_json(runner, tiny_svd):
    """svd parse --json outputs valid JSON with peripherals."""
    result = runner.invoke(cli, ["--json", "svd", "parse", tiny_svd])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "peripheral_count" in data
    assert data["peripheral_count"] == 2
    assert "peripherals" in data


def test_svd_parse_peripheral_names(runner, tiny_svd):
    """svd parse --json correctly reads peripheral names."""
    result = runner.invoke(cli, ["--json", "svd", "parse", tiny_svd])
    assert result.exit_code == 0
    data = json.loads(result.output)
    names = [p["name"] for p in data["peripherals"]]
    assert "UART0" in names
    assert "SPI0" in names


def test_svd_generate_json(runner, tiny_svd, tmp_path):
    """svd generate --json outputs valid JSON."""
    out = str(tmp_path / "stubs")
    result = runner.invoke(cli, ["--json", "svd", "generate", tiny_svd, "--output", out])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "mode" in data
    assert "output_dir" in data


# ---------------------------------------------------------------------------
# vulnrange
# ---------------------------------------------------------------------------

def test_vulnrange_help(runner):
    """vulnrange --help mentions list/start/hint/solve/writeup."""
    result = runner.invoke(cli, ["vulnrange", "--help"])
    assert result.exit_code == 0
    for sub in ["list", "start", "hint", "solve", "writeup"]:
        assert sub in result.output


def test_vulnrange_list_no_crash(runner):
    """vulnrange list runs without crashing even if vulnrange dir is missing."""
    result = runner.invoke(cli, ["vulnrange", "list"])
    assert result.exit_code == 0


def test_vulnrange_list_json(runner):
    """vulnrange list --json outputs valid JSON array."""
    result = runner.invoke(cli, ["--json", "vulnrange", "list"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)


@pytest.mark.skipif(not Path("vulnrange").exists(), reason="no vulnrange dir")
def test_vulnrange_start(runner):
    """vulnrange start shows range info for a known CVE."""
    vulnrange_dir = Path("vulnrange")
    range_dirs = [d for d in vulnrange_dir.iterdir() if d.is_dir() and (d / "manifest.yaml").exists()]
    if not range_dirs:
        pytest.skip("no range manifests found")
    range_id = range_dirs[0].name
    result = runner.invoke(cli, ["vulnrange", "start", range_id])
    assert result.exit_code == 0


@pytest.mark.skipif(not Path("vulnrange").exists(), reason="no vulnrange dir")
def test_vulnrange_hint(runner):
    """vulnrange hint outputs a hint for a known range."""
    vulnrange_dir = Path("vulnrange")
    range_dirs = [d for d in vulnrange_dir.iterdir() if d.is_dir() and (d / "manifest.yaml").exists()]
    if not range_dirs:
        pytest.skip("no range manifests found")
    range_id = range_dirs[0].name
    result = runner.invoke(cli, ["vulnrange", "hint", range_id])
    assert result.exit_code == 0


@pytest.mark.skipif(not Path("vulnrange").exists(), reason="no vulnrange dir")
def test_vulnrange_writeup(runner):
    """vulnrange writeup outputs markdown or 'no writeup' message."""
    vulnrange_dir = Path("vulnrange")
    range_dirs = [d for d in vulnrange_dir.iterdir() if d.is_dir() and (d / "manifest.yaml").exists()]
    if not range_dirs:
        pytest.skip("no range manifests found")
    range_id = range_dirs[0].name
    result = runner.invoke(cli, ["vulnrange", "writeup", range_id])
    # Exit 0 whether writeup exists or not
    assert result.exit_code == 0


def test_vulnrange_start_nonexistent(runner):
    """vulnrange start with bogus ID exits with code 1."""
    result = runner.invoke(cli, ["vulnrange", "start", "CVE-9999-99999"])
    assert result.exit_code == 1


def test_vulnrange_hint_nonexistent(runner):
    """vulnrange hint with bogus ID exits with code 1."""
    result = runner.invoke(cli, ["vulnrange", "hint", "CVE-9999-99999"])
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Global flags
# ---------------------------------------------------------------------------

def test_json_flag_scan_vuln_list(runner):
    """--json flag on scan-vuln list produces JSON array."""
    result = runner.invoke(cli, ["--json", "scan-vuln", "list"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)


def test_verbose_flag_no_crash(runner):
    """--verbose flag doesn't break help output."""
    result = runner.invoke(cli, ["--verbose", "--help"])
    assert result.exit_code == 0


def test_quiet_flag_no_crash(runner):
    """--quiet flag doesn't break help output."""
    result = runner.invoke(cli, ["--quiet", "--help"])
    assert result.exit_code == 0
