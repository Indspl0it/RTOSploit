"""Tests for FuzzInputStream and InputExhausted."""

from __future__ import annotations


import pytest

from rtosploit.fuzzing.fuzz_input import FuzzInputStream, InputExhausted


class TestInputExhausted:
    """Tests for the InputExhausted exception."""

    def test_is_exception(self):
        assert isinstance(InputExhausted(), Exception)

    def test_can_be_raised_and_caught(self):
        with pytest.raises(InputExhausted):
            raise InputExhausted("test message")

    def test_message_preserved(self):
        try:
            raise InputExhausted("buffer empty")
        except InputExhausted as e:
            assert "buffer empty" in str(e)


class TestFuzzInputStreamConstruction:
    """Tests for FuzzInputStream initialization."""

    def test_empty_data(self):
        stream = FuzzInputStream(b"")
        assert stream.is_exhausted
        assert stream.remaining == 0

    def test_nonempty_data(self):
        stream = FuzzInputStream(b"\x01\x02\x03")
        assert not stream.is_exhausted
        assert stream.remaining == 3

    def test_initial_stats(self):
        stream = FuzzInputStream(b"\x01\x02")
        stats = stream.stats
        assert stats["total_size"] == 2
        assert stats["position"] == 0
        assert stats["remaining"] == 2
        assert stats["bytes_consumed"] == 0
        assert stats["read_count"] == 0


class TestFuzzInputStreamExhaustion:
    """Tests for stream exhaustion behavior."""

    def test_empty_stream_is_exhausted(self):
        assert FuzzInputStream(b"").is_exhausted is True

    def test_nonempty_stream_not_exhausted(self):
        assert FuzzInputStream(b"\x01").is_exhausted is False

    def test_exhausted_after_consuming_all(self):
        stream = FuzzInputStream(b"\x01")
        stream.read_u8()
        assert stream.is_exhausted is True

    def test_remaining_decreases(self):
        stream = FuzzInputStream(b"\x01\x02\x03")
        assert stream.remaining == 3
        stream.read_u8()
        assert stream.remaining == 2
        stream.read_u8()
        assert stream.remaining == 1
        stream.read_u8()
        assert stream.remaining == 0


class TestReadBytes:
    """Tests for read_bytes."""

    def test_read_bytes_basic(self):
        stream = FuzzInputStream(b"\x01\x02\x03")
        assert stream.read_bytes(2) == b"\x01\x02"

    def test_read_bytes_sequential(self):
        stream = FuzzInputStream(b"\x01\x02\x03")
        assert stream.read_bytes(2) == b"\x01\x02"
        assert stream.read_bytes(1) == b"\x03"

    def test_read_bytes_exact_size(self):
        stream = FuzzInputStream(b"\xAA\xBB")
        assert stream.read_bytes(2) == b"\xAA\xBB"
        assert stream.is_exhausted

    def test_read_bytes_exhaustion(self):
        stream = FuzzInputStream(b"\x01\x02\x03")
        stream.read_bytes(2)
        stream.read_bytes(1)
        with pytest.raises(InputExhausted):
            stream.read_bytes(1)

    def test_read_bytes_empty_stream(self):
        stream = FuzzInputStream(b"")
        with pytest.raises(InputExhausted):
            stream.read_bytes(1)

    def test_read_bytes_too_many(self):
        stream = FuzzInputStream(b"\x01\x02")
        with pytest.raises(InputExhausted):
            stream.read_bytes(3)


class TestReadU8:
    """Tests for read_u8."""

    def test_read_u8_zero(self):
        assert FuzzInputStream(b"\x00").read_u8() == 0

    def test_read_u8_max(self):
        assert FuzzInputStream(b"\xFF").read_u8() == 255

    def test_read_u8_value(self):
        assert FuzzInputStream(b"\x42").read_u8() == 0x42

    def test_read_u8_exhaustion(self):
        stream = FuzzInputStream(b"\x01")
        stream.read_u8()
        with pytest.raises(InputExhausted):
            stream.read_u8()


class TestReadU16:
    """Tests for read_u16 (little-endian)."""

    def test_read_u16_one(self):
        assert FuzzInputStream(b"\x01\x00").read_u16() == 1

    def test_read_u16_max(self):
        assert FuzzInputStream(b"\xFF\xFF").read_u16() == 65535

    def test_read_u16_little_endian(self):
        # 0xCDAB in little-endian is bytes AB CD
        assert FuzzInputStream(b"\xAB\xCD").read_u16() == 0xCDAB

    def test_read_u16_exhaustion(self):
        stream = FuzzInputStream(b"\x01")
        with pytest.raises(InputExhausted):
            stream.read_u16()


class TestReadU32:
    """Tests for read_u32 (little-endian)."""

    def test_read_u32_one(self):
        assert FuzzInputStream(b"\x01\x00\x00\x00").read_u32() == 1

    def test_read_u32_max(self):
        assert FuzzInputStream(b"\xFF\xFF\xFF\xFF").read_u32() == 0xFFFFFFFF

    def test_read_u32_little_endian(self):
        # 0x01EFCDAB in little-endian is bytes AB CD EF 01
        assert FuzzInputStream(b"\xAB\xCD\xEF\x01").read_u32() == 0x01EFCDAB

    def test_read_u32_exhaustion(self):
        stream = FuzzInputStream(b"\x01\x02")
        with pytest.raises(InputExhausted):
            stream.read_u32()


class TestReadValue:
    """Tests for read_value dispatch."""

    def test_read_value_size_1(self):
        assert FuzzInputStream(b"\xAB").read_value(1) == 0xAB

    def test_read_value_size_2(self):
        assert FuzzInputStream(b"\xAB\xCD").read_value(2) == 0xCDAB

    def test_read_value_size_4(self):
        assert FuzzInputStream(b"\xAB\xCD\xEF\x01").read_value(4) == 0x01EFCDAB

    def test_read_value_invalid_size(self):
        with pytest.raises(ValueError, match="Unsupported read size"):
            FuzzInputStream(b"\x00\x00\x00\x00\x00\x00\x00\x00").read_value(8)

    def test_read_value_size_3_invalid(self):
        with pytest.raises(ValueError, match="Unsupported read size"):
            FuzzInputStream(b"\x00\x00\x00").read_value(3)


class TestStats:
    """Tests for stats tracking."""

    def test_stats_after_reads(self):
        stream = FuzzInputStream(b"\x01\x02\x03\x04\x05\x06\x07")
        stream.read_u8()
        stream.read_u16()
        stats = stream.stats
        assert stats["bytes_consumed"] == 3
        assert stats["read_count"] == 2
        assert stats["position"] == 3
        assert stats["remaining"] == 4

    def test_stats_total_size_constant(self):
        stream = FuzzInputStream(b"\x01\x02\x03")
        stream.read_u8()
        assert stream.stats["total_size"] == 3


class TestReset:
    """Tests for reset behavior."""

    def test_reset_rewinds(self):
        stream = FuzzInputStream(b"\x01\x02\x03")
        stream.read_u8()
        stream.read_u8()
        stream.reset()
        assert not stream.is_exhausted
        assert stream.remaining == 3

    def test_reset_reads_same_data(self):
        stream = FuzzInputStream(b"\x42\x43")
        first = stream.read_u8()
        stream.reset()
        second = stream.read_u8()
        assert first == second == 0x42

    def test_reset_clears_stats(self):
        stream = FuzzInputStream(b"\x01\x02\x03")
        stream.read_u8()
        stream.reset()
        assert stream.stats["bytes_consumed"] == 0
        assert stream.stats["read_count"] == 0
        assert stream.stats["position"] == 0

    def test_reset_after_exhaustion(self):
        stream = FuzzInputStream(b"\x01")
        stream.read_u8()
        assert stream.is_exhausted
        stream.reset()
        assert not stream.is_exhausted
        assert stream.read_u8() == 0x01
