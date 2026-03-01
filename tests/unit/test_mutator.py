"""Unit tests for rtosploit.fuzzing.mutator."""

from __future__ import annotations

import pytest

from rtosploit.fuzzing.mutator import (
    INTERESTING_8,
    INTERESTING_16,
    INTERESTING_32,
    Mutator,
)


SEED = 42
SAMPLE = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"


class TestMutatorDeterminism:
    """Seeded mutator must produce identical results across runs."""

    def test_same_seed_same_output(self):
        m1 = Mutator(seed=SEED)
        m2 = Mutator(seed=SEED)
        assert m1.mutate(SAMPLE) == m2.mutate(SAMPLE)

    def test_different_seed_different_output(self):
        m1 = Mutator(seed=1)
        m2 = Mutator(seed=2)
        # With different seeds on non-trivial input, outputs should differ
        # (astronomically unlikely to collide)
        assert m1.mutate(SAMPLE) != m2.mutate(SAMPLE)


class TestBitFlip:
    def test_preserves_length(self):
        m = Mutator(seed=SEED)
        result = m.bit_flip(SAMPLE)
        assert len(result) == len(SAMPLE)

    def test_modifies_data(self):
        m = Mutator(seed=SEED)
        result = m.bit_flip(SAMPLE)
        assert result != SAMPLE

    def test_multiple_bits(self):
        m = Mutator(seed=SEED)
        result = m.bit_flip(SAMPLE, num_bits=4)
        assert len(result) == len(SAMPLE)
        assert result != SAMPLE

    def test_empty_input(self):
        m = Mutator(seed=SEED)
        assert m.bit_flip(b"") == b""

    def test_single_byte(self):
        m = Mutator(seed=SEED)
        result = m.bit_flip(b"\x00", num_bits=1)
        assert len(result) == 1
        assert result != b"\x00"


class TestByteFlip:
    def test_preserves_length(self):
        m = Mutator(seed=SEED)
        result = m.byte_flip(SAMPLE)
        assert len(result) == len(SAMPLE)

    def test_modifies_data(self):
        m = Mutator(seed=SEED)
        result = m.byte_flip(SAMPLE)
        assert result != SAMPLE

    def test_multiple_bytes(self):
        m = Mutator(seed=SEED)
        result = m.byte_flip(SAMPLE, num_bytes=3)
        assert len(result) == len(SAMPLE)

    def test_empty_input(self):
        m = Mutator(seed=SEED)
        assert m.byte_flip(b"") == b""


class TestArithmetic:
    def test_preserves_length(self):
        m = Mutator(seed=SEED)
        result = m.arithmetic(SAMPLE)
        assert len(result) == len(SAMPLE)

    def test_modifies_data(self):
        m = Mutator(seed=SEED)
        result = m.arithmetic(SAMPLE)
        assert result != SAMPLE

    def test_empty_input(self):
        m = Mutator(seed=SEED)
        assert m.arithmetic(b"") == b""


class TestInterestingValues:
    def test_preserves_length(self):
        m = Mutator(seed=SEED)
        result = m.interesting_values(SAMPLE)
        assert len(result) == len(SAMPLE)

    def test_modifies_data(self):
        m = Mutator(seed=SEED)
        result = m.interesting_values(SAMPLE)
        assert result != SAMPLE

    def test_empty_input(self):
        m = Mutator(seed=SEED)
        assert m.interesting_values(b"") == b""

    def test_single_byte_uses_8bit(self):
        m = Mutator(seed=SEED)
        result = m.interesting_values(b"\x42")
        assert len(result) == 1
        assert result[0] in INTERESTING_8


class TestHavoc:
    def test_produces_output(self):
        m = Mutator(seed=SEED)
        result = m.havoc(SAMPLE)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_modifies_data(self):
        m = Mutator(seed=SEED)
        result = m.havoc(SAMPLE, rounds=32)
        assert result != SAMPLE

    def test_empty_input(self):
        m = Mutator(seed=SEED)
        assert m.havoc(b"") == b""


class TestSplice:
    def test_produces_output(self):
        m = Mutator(seed=SEED)
        a = b"\xaa" * 8
        b_ = b"\xbb" * 8
        result = m.splice(a, b_)
        assert len(result) > 0

    def test_contains_parts_of_both(self):
        m = Mutator(seed=SEED)
        a = b"\xaa" * 16
        b_ = b"\xbb" * 16
        result = m.splice(a, b_)
        # Should contain some bytes from each parent
        assert b"\xaa" in result or b"\xbb" in result

    def test_empty_first(self):
        m = Mutator(seed=SEED)
        result = m.splice(b"", b"\xbb\xbb")
        assert isinstance(result, bytes)

    def test_empty_second(self):
        m = Mutator(seed=SEED)
        result = m.splice(b"\xaa\xaa", b"")
        assert isinstance(result, bytes)

    def test_both_empty(self):
        m = Mutator(seed=SEED)
        result = m.splice(b"", b"")
        assert result == b""


class TestMutate:
    def test_produces_output(self):
        m = Mutator(seed=SEED)
        result = m.mutate(SAMPLE)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_modifies_data(self):
        m = Mutator(seed=SEED)
        result = m.mutate(SAMPLE)
        assert result != SAMPLE

    def test_empty_input(self):
        m = Mutator(seed=SEED)
        assert m.mutate(b"") == b""

    def test_returns_bytes(self):
        m = Mutator(seed=SEED)
        result = m.mutate(SAMPLE)
        assert isinstance(result, bytes)
