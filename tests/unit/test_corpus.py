"""Tests for CorpusManager – coverage-guided corpus management."""

from __future__ import annotations

from pathlib import Path

import pytest

from rtosploit.coverage.bitmap_reader import BITMAP_SIZE
from rtosploit.fuzzing.corpus import CorpusManager


# ── Helpers ──────────────────────────────────────────────────────────────────


def _bitmap_with_edge(edge_index: int, value: int = 1) -> bytes:
    """Return a bitmap with a single edge hit."""
    buf = bytearray(BITMAP_SIZE)
    buf[edge_index] = value
    return bytes(buf)


# ── add() ────────────────────────────────────────────────────────────────────


class TestAdd:
    def test_returns_true_for_new_coverage(self, tmp_path: Path) -> None:
        mgr = CorpusManager(str(tmp_path / "corpus"))
        bitmap = _bitmap_with_edge(42)
        assert mgr.add(b"input1", bitmap) is True

    def test_returns_false_for_duplicate_coverage(self, tmp_path: Path) -> None:
        mgr = CorpusManager(str(tmp_path / "corpus"))
        bitmap = _bitmap_with_edge(42)
        mgr.add(b"input1", bitmap)
        assert mgr.add(b"input2", bitmap) is False

    def test_accepts_different_edges(self, tmp_path: Path) -> None:
        mgr = CorpusManager(str(tmp_path / "corpus"))
        assert mgr.add(b"a", _bitmap_with_edge(10)) is True
        assert mgr.add(b"b", _bitmap_with_edge(20)) is True

    def test_increments_size(self, tmp_path: Path) -> None:
        mgr = CorpusManager(str(tmp_path / "corpus"))
        assert mgr.size == 0
        mgr.add(b"a", _bitmap_with_edge(5))
        assert mgr.size == 1

    def test_rejects_all_zero_bitmap(self, tmp_path: Path) -> None:
        mgr = CorpusManager(str(tmp_path / "corpus"))
        zero_bitmap = bytes(BITMAP_SIZE)
        assert mgr.add(b"noop", zero_bitmap) is False


# ── get_random() ─────────────────────────────────────────────────────────────


class TestGetRandom:
    def test_returns_default_seed_when_empty(self, tmp_path: Path) -> None:
        mgr = CorpusManager(str(tmp_path / "corpus"))
        result = mgr.get_random()
        assert result == b"\x00" * 64

    def test_returns_entry_from_corpus(self, tmp_path: Path) -> None:
        mgr = CorpusManager(str(tmp_path / "corpus"))
        mgr.add(b"only_input", _bitmap_with_edge(0))
        # With a single entry, get_random must return it.
        assert mgr.get_random() == b"only_input"


# ── save_to_disk / load_from_disk ────────────────────────────────────────────


class TestDiskPersistence:
    def test_save_creates_files(self, tmp_path: Path) -> None:
        corpus_dir = tmp_path / "corpus"
        mgr = CorpusManager(str(corpus_dir))
        mgr.add(b"data1", _bitmap_with_edge(1))
        mgr.add(b"data2", _bitmap_with_edge(2))
        mgr.save_to_disk()

        files = sorted(corpus_dir.iterdir())
        assert len(files) == 2

    def test_load_reads_back(self, tmp_path: Path) -> None:
        corpus_dir = tmp_path / "corpus"
        mgr = CorpusManager(str(corpus_dir))
        mgr.add(b"alpha", _bitmap_with_edge(10))
        mgr.save_to_disk()

        mgr2 = CorpusManager(str(corpus_dir))
        mgr2.load_from_disk()
        assert mgr2.size == 1
        assert mgr2.get_random() == b"alpha"

    def test_save_is_idempotent(self, tmp_path: Path) -> None:
        corpus_dir = tmp_path / "corpus"
        mgr = CorpusManager(str(corpus_dir))
        mgr.add(b"data", _bitmap_with_edge(3))
        mgr.save_to_disk()
        mgr.save_to_disk()  # second call should not duplicate files

        files = list(corpus_dir.iterdir())
        assert len(files) == 1


# ── coverage_percentage() ────────────────────────────────────────────────────


class TestCoveragePercentage:
    def test_zero_when_empty(self, tmp_path: Path) -> None:
        mgr = CorpusManager(str(tmp_path / "corpus"))
        assert mgr.coverage_percentage() == 0.0

    def test_correct_value(self, tmp_path: Path) -> None:
        mgr = CorpusManager(str(tmp_path / "corpus"))
        mgr.add(b"a", _bitmap_with_edge(0))
        mgr.add(b"b", _bitmap_with_edge(1))
        expected = (2 / BITMAP_SIZE) * 100.0
        assert mgr.coverage_percentage() == pytest.approx(expected)

    def test_zero_bitmap_size(self, tmp_path: Path) -> None:
        mgr = CorpusManager(str(tmp_path / "corpus"), bitmap_size=0)
        assert mgr.coverage_percentage() == 0.0


# ── Round-trip ───────────────────────────────────────────────────────────────


class TestRoundTrip:
    def test_add_save_load_roundtrip(self, tmp_path: Path) -> None:
        corpus_dir = tmp_path / "corpus"
        mgr = CorpusManager(str(corpus_dir))
        mgr.add(b"input_a", _bitmap_with_edge(100))
        mgr.add(b"input_b", _bitmap_with_edge(200))
        mgr.save_to_disk()

        mgr2 = CorpusManager(str(corpus_dir))
        mgr2.load_from_disk()

        assert mgr2.size == 2
        loaded = {mgr2._entries[0], mgr2._entries[1]}
        assert loaded == {b"input_a", b"input_b"}
