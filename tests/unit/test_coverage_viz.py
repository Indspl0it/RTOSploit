"""Tests for Phase 4: Coverage Visualization & Heatmap.

Covers BitmapReader, CoverageMapper, CoverageVisualizer, and CLI commands.
Uses self-contained ARM Thumb firmware bytes for disassembly tests.
"""

from __future__ import annotations

import struct
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from rtosploit.coverage.bitmap_reader import BitmapReader, CoverageMap, BITMAP_SIZE
from rtosploit.coverage.mapper import CoverageMapper
from rtosploit.coverage.visualizer import CoverageVisualizer
from rtosploit.cli.main import cli


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def tiny_arm_thumb_firmware(tmp_path) -> str:
    """Create a minimal ARM Thumb firmware binary for disassembly.

    Contains a few real Thumb instructions:
      0x08000000: movs r0, #0      (2000)
      0x08000002: movs r1, #1      (2101)
      0x08000004: adds r0, r0, r1  (1840)
      0x08000006: nop               (bf00)
      0x08000008: b .              (e7fe) -- infinite loop
    """
    fw = tmp_path / "thumb_fw.bin"
    # Thumb encoding (little-endian 16-bit)
    instructions = [
        0x2000,  # movs r0, #0
        0x2101,  # movs r1, #1
        0x1840,  # adds r0, r0, r1
        0xBF00,  # nop
        0xE7FE,  # b . (infinite loop)
    ]
    data = b"".join(struct.pack("<H", insn) for insn in instructions)
    fw.write_bytes(data)
    return str(fw)


@pytest.fixture
def sample_trace_file(tmp_path) -> str:
    """Create a sample trace log with hex address pairs."""
    trace = tmp_path / "trace.log"
    lines = [
        "# RTOSploit trace log",
        "0x08000000,0x08000002",
        "0x08000002,0x08000004",
        "0x08000004,0x08000006",
        "0x08000006,0x08000008",
        "0x08000000,0x08000002",  # repeat for hit count
        "0x08000002,0x08000004",  # repeat for hit count
    ]
    trace.write_text("\n".join(lines) + "\n")
    return str(trace)


@pytest.fixture
def sample_bitmap() -> bytes:
    """Create a synthetic 64KB bitmap with a few non-zero entries."""
    data = bytearray(BITMAP_SIZE)
    data[42] = 5
    data[100] = 1
    data[1000] = 255
    data[65535] = 3
    return bytes(data)


@pytest.fixture
def sample_bitmap_file(tmp_path, sample_bitmap) -> str:
    """Write a sample bitmap to a file."""
    bm = tmp_path / "bitmap.bin"
    bm.write_bytes(sample_bitmap)
    return str(bm)


# ── CoverageMap ───────────────────────────────────────────────────────────────


def test_coverage_map_creation():
    """CoverageMap can be created with defaults."""
    cov = CoverageMap()
    assert cov.covered_addresses == set()
    assert cov.covered_edges == []
    assert cov.hot_addresses == {}
    assert cov.total_instructions == 0
    assert cov.covered_instructions == 0


def test_coverage_map_coverage_percent_zero():
    """coverage_percent is 0.0 when total_instructions is 0."""
    cov = CoverageMap()
    assert cov.coverage_percent == 0.0


def test_coverage_map_coverage_percent_calculated():
    """coverage_percent computes correctly."""
    cov = CoverageMap(total_instructions=200, covered_instructions=50)
    assert cov.coverage_percent == 25.0


# ── BitmapReader ──────────────────────────────────────────────────────────────


def test_compute_edge_id_matches_rust():
    """compute_edge_id matches the Rust implementation: ((from >> 1) ^ to) % 65536."""
    reader = BitmapReader()
    # Test vectors (manually computed)
    assert reader.compute_edge_id(0x0800_0000, 0x0800_0100) == (
        (0x0800_0000 >> 1) ^ 0x0800_0100
    ) % BITMAP_SIZE
    assert reader.compute_edge_id(0, 0) == 0
    assert reader.compute_edge_id(2, 1) == (1 ^ 1) % BITMAP_SIZE  # (2>>1)^1 = 0
    assert reader.compute_edge_id(0xFFFF_FFFF, 0xDEAD_BEEF) == (
        (0xFFFF_FFFF >> 1) ^ 0xDEAD_BEEF
    ) % BITMAP_SIZE


def test_compute_edge_id_always_in_range():
    """Edge IDs are always within [0, BITMAP_SIZE)."""
    test_addrs = [0, 1, 0x0800_0000, 0xFFFF_FFFF, 12345, 0xDEAD_BEEF]
    for from_a in test_addrs:
        for to_a in test_addrs:
            eid = BitmapReader.compute_edge_id(from_a, to_a)
            assert 0 <= eid < BITMAP_SIZE, f"edge_id {eid} out of range for ({from_a}, {to_a})"


def test_read_bytes_parses_bitmap(sample_bitmap):
    """read_bytes returns only non-zero entries."""
    reader = BitmapReader()
    result = reader.read_bytes(sample_bitmap)
    assert result[42] == 5
    assert result[100] == 1
    assert result[1000] == 255
    assert result[65535] == 3
    assert len(result) == 4
    assert 0 not in result  # zero entries excluded


def test_count_edges(sample_bitmap):
    """count_edges returns the number of non-zero entries."""
    reader = BitmapReader()
    assert reader.count_edges(sample_bitmap) == 4


def test_read_file_valid(sample_bitmap_file):
    """read_file successfully reads a valid 64KB bitmap."""
    reader = BitmapReader()
    data = reader.read_file(sample_bitmap_file)
    assert len(data) == BITMAP_SIZE


def test_read_file_wrong_size(tmp_path):
    """read_file raises ValueError for wrong-sized files."""
    bad_file = tmp_path / "bad_bitmap.bin"
    bad_file.write_bytes(b"\x00" * 100)
    reader = BitmapReader()
    with pytest.raises(ValueError, match="expected 65536 bytes"):
        reader.read_file(str(bad_file))


# ── CoverageMapper ────────────────────────────────────────────────────────────


def test_mapper_map_from_trace(tiny_arm_thumb_firmware, sample_trace_file):
    """map_from_trace parses trace log and counts hits."""
    mapper = CoverageMapper(tiny_arm_thumb_firmware, base_address=0x0800_0000)
    cov = mapper.map_from_trace(sample_trace_file)

    # All addresses from the trace should be covered
    assert 0x08000000 in cov.covered_addresses
    assert 0x08000002 in cov.covered_addresses
    assert 0x08000004 in cov.covered_addresses
    assert 0x08000006 in cov.covered_addresses
    assert 0x08000008 in cov.covered_addresses

    # Edges parsed
    assert len(cov.covered_edges) == 6  # 6 non-comment, non-blank lines

    # Hit counts: 0x08000002 appears 4 times (as from and to)
    assert cov.hot_addresses[0x08000000] >= 2
    assert cov.hot_addresses[0x08000002] >= 2


def test_mapper_disassemble_firmware(tiny_arm_thumb_firmware):
    """disassemble_firmware returns ARM Thumb instructions."""
    mapper = CoverageMapper(tiny_arm_thumb_firmware, base_address=0x0800_0000)
    disasm = mapper.disassemble_firmware()

    assert len(disasm) == 5
    # Check first instruction
    addr, mnemonic, op_str = disasm[0]
    assert addr == 0x0800_0000
    assert mnemonic == "movs"
    # Check last instruction (infinite loop)
    addr_last, mnemonic_last, _ = disasm[4]
    assert addr_last == 0x0800_0008
    assert mnemonic_last == "b"


# ── CoverageVisualizer ───────────────────────────────────────────────────────


def test_visualizer_render_terminal(tiny_arm_thumb_firmware, sample_trace_file):
    """render_terminal produces Rich markup with expected formatting."""
    mapper = CoverageMapper(tiny_arm_thumb_firmware, base_address=0x0800_0000)
    cov = mapper.map_from_trace(sample_trace_file)
    disasm = mapper.disassemble_firmware()
    cov.total_instructions = len(disasm)

    viz = CoverageVisualizer(cov, disasm)
    output = viz.render_terminal(max_lines=50)

    assert "Coverage Summary" in output
    assert "0x08000000" in output
    assert "Instructions:" in output
    # Should have color markup
    assert "[" in output  # Rich tags present


def test_visualizer_get_stats(tiny_arm_thumb_firmware, sample_trace_file):
    """get_stats returns expected keys and correct values."""
    mapper = CoverageMapper(tiny_arm_thumb_firmware, base_address=0x0800_0000)
    cov = mapper.map_from_trace(sample_trace_file)
    disasm = mapper.disassemble_firmware()
    cov.total_instructions = len(disasm)
    all_addrs = {addr for addr, _, _ in disasm}
    cov.covered_instructions = len(cov.covered_addresses & all_addrs)

    viz = CoverageVisualizer(cov, disasm)
    stats = viz.get_stats()

    assert "total_instructions" in stats
    assert "covered_instructions" in stats
    assert "coverage_percent" in stats
    assert "total_edges" in stats
    assert "hot_spots" in stats
    assert stats["total_instructions"] == 5
    assert stats["covered_instructions"] == 5  # all 5 instruction addresses are in trace
    assert stats["coverage_percent"] == 100.0
    assert stats["total_edges"] == 6
    # hot_spots is a list of (addr, count) tuples, at most 10
    assert len(stats["hot_spots"]) <= 10


def test_visualizer_render_html(tiny_arm_thumb_firmware, sample_trace_file):
    """render_html produces valid HTML with expected content."""
    mapper = CoverageMapper(tiny_arm_thumb_firmware, base_address=0x0800_0000)
    cov = mapper.map_from_trace(sample_trace_file)
    disasm = mapper.disassemble_firmware()
    cov.total_instructions = len(disasm)

    viz = CoverageVisualizer(cov, disasm)
    html = viz.render_html()

    assert "<!DOCTYPE html>" in html
    assert "RTOSploit Coverage Report" in html
    assert "0x08000000" in html
    assert "scrollToAddress" in html  # JavaScript function


def test_visualizer_write_html(tiny_arm_thumb_firmware, sample_trace_file, tmp_path):
    """write_html creates an HTML file on disk."""
    mapper = CoverageMapper(tiny_arm_thumb_firmware, base_address=0x0800_0000)
    cov = mapper.map_from_trace(sample_trace_file)
    disasm = mapper.disassemble_firmware()
    cov.total_instructions = len(disasm)

    viz = CoverageVisualizer(cov, disasm)
    out_path = str(tmp_path / "report.html")
    viz.write_html(out_path)

    assert Path(out_path).exists()
    content = Path(out_path).read_text()
    assert "RTOSploit Coverage Report" in content


# ── CLI Commands ──────────────────────────────────────────────────────────────


def test_coverage_help(runner):
    """coverage --help lists view and stats subcommands."""
    result = runner.invoke(cli, ["coverage", "--help"])
    assert result.exit_code == 0
    assert "view" in result.output
    assert "stats" in result.output


def test_coverage_view_help(runner):
    """coverage view --help shows firmware, bitmap, trace options."""
    result = runner.invoke(cli, ["coverage", "view", "--help"])
    assert result.exit_code == 0
    assert "--firmware" in result.output
    assert "--bitmap" in result.output
    assert "--trace" in result.output
    assert "--format" in result.output
    assert "--output" in result.output


def test_coverage_stats_help(runner):
    """coverage stats --help shows firmware, bitmap, trace options."""
    result = runner.invoke(cli, ["coverage", "stats", "--help"])
    assert result.exit_code == 0
    assert "--firmware" in result.output
    assert "--bitmap" in result.output
    assert "--trace" in result.output
