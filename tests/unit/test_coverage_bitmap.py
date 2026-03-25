"""Tests for rtosploit.coverage.bitmap — CoverageBitmap and FERMCovCollector."""

from __future__ import annotations


from rtosploit.coverage.bitmap import CoverageBitmap, FERMCovCollector
from rtosploit.coverage.bitmap_reader import BITMAP_SIZE


# ======================================================================
# CoverageBitmap
# ======================================================================


class TestCoverageBitmapConstruction:
    def test_default_size(self):
        bm = CoverageBitmap()
        assert bm.size == BITMAP_SIZE
        assert len(bm) == BITMAP_SIZE

    def test_custom_size(self):
        bm = CoverageBitmap(size=1024)
        assert bm.size == 1024

    def test_initially_zeroed(self):
        bm = CoverageBitmap()
        assert bm.count_edges() == 0
        assert bm.count_hits() == 0

    def test_to_bytes_length(self):
        bm = CoverageBitmap()
        assert len(bm.to_bytes()) == BITMAP_SIZE

    def test_to_bytes_initially_all_zero(self):
        bm = CoverageBitmap(size=16)
        assert bm.to_bytes() == b"\x00" * 16


class TestCoverageBitmapRecordEdge:
    def test_single_edge(self):
        bm = CoverageBitmap()
        bm.record_edge(0x1000, 0x2000)
        assert bm.count_edges() == 1
        assert bm.count_hits() == 1

    def test_same_edge_increments(self):
        bm = CoverageBitmap()
        bm.record_edge(0x1000, 0x2000)
        bm.record_edge(0x1000, 0x2000)
        assert bm.count_edges() == 1
        assert bm.count_hits() == 2

    def test_different_edges(self):
        bm = CoverageBitmap()
        bm.record_edge(0x1000, 0x2000)
        bm.record_edge(0x3000, 0x4000)
        assert bm.count_edges() == 2

    def test_saturates_at_255(self):
        bm = CoverageBitmap(size=256)
        for _ in range(300):
            bm.record_edge(0x100, 0x200)
        edge_id = ((0x100 >> 1) ^ 0x200) % 256
        assert bm[edge_id] == 255

    def test_edge_id_formula(self):
        """Edge ID = ((prev >> 1) ^ current) % size."""
        bm = CoverageBitmap(size=256)
        prev, cur = 0x100, 0x200
        expected_id = ((prev >> 1) ^ cur) % 256
        bm.record_edge(prev, cur)
        assert bm[expected_id] == 1


class TestCoverageBitmapHasNewCoverage:
    def test_empty_has_no_new(self):
        bm = CoverageBitmap()
        global_bm = CoverageBitmap()
        assert bm.has_new_coverage(global_bm) is False

    def test_new_edge_detected(self):
        bm = CoverageBitmap()
        bm.record_edge(0x1000, 0x2000)
        global_bm = CoverageBitmap()
        assert bm.has_new_coverage(global_bm) is True

    def test_already_known_edge(self):
        bm = CoverageBitmap()
        bm.record_edge(0x1000, 0x2000)
        global_bm = CoverageBitmap()
        global_bm.record_edge(0x1000, 0x2000)
        assert bm.has_new_coverage(global_bm) is False

    def test_superset_has_no_new(self):
        """Global has more edges than local -- local has nothing new."""
        local = CoverageBitmap()
        local.record_edge(0x1000, 0x2000)
        global_bm = CoverageBitmap()
        global_bm.record_edge(0x1000, 0x2000)
        global_bm.record_edge(0x3000, 0x4000)
        assert local.has_new_coverage(global_bm) is False


class TestCoverageBitmapMerge:
    def test_merge_adds_edges(self):
        local = CoverageBitmap(size=256)
        local.record_edge(0x100, 0x200)
        target = CoverageBitmap(size=256)
        local.merge_into(target)
        assert target.count_edges() == 1

    def test_merge_takes_max(self):
        local = CoverageBitmap(size=256)
        local.record_edge(0x100, 0x200)
        local.record_edge(0x100, 0x200)  # hit count = 2
        target = CoverageBitmap(size=256)
        target.record_edge(0x100, 0x200)  # hit count = 1
        local.merge_into(target)
        edge_id = ((0x100 >> 1) ^ 0x200) % 256
        assert target[edge_id] == 2

    def test_merge_preserves_existing(self):
        local = CoverageBitmap(size=256)
        local.record_edge(0x100, 0x200)
        target = CoverageBitmap(size=256)
        target.record_edge(0x10, 0x20)  # bucket 40, different from 0x100->0x200 (bucket 128)
        local.merge_into(target)
        assert target.count_edges() == 2


class TestCoverageBitmapReset:
    def test_reset_clears(self):
        bm = CoverageBitmap()
        bm.record_edge(0x1000, 0x2000)
        bm.record_edge(0x3000, 0x4000)
        bm.reset()
        assert bm.count_edges() == 0
        assert bm.count_hits() == 0


class TestCoverageBitmapSerialization:
    def test_roundtrip(self):
        bm = CoverageBitmap(size=256)
        bm.record_edge(0x100, 0x200)
        bm.record_edge(0x300, 0x400)
        data = bm.to_bytes()
        restored = CoverageBitmap.from_bytes(data)
        assert restored.to_bytes() == data

    def test_from_bytes_size(self):
        data = bytes(512)
        bm = CoverageBitmap.from_bytes(data)
        assert bm.size == 512

    def test_from_bytes_preserves_content(self):
        data = bytearray(256)
        data[42] = 7
        bm = CoverageBitmap.from_bytes(bytes(data))
        assert bm[42] == 7


# ======================================================================
# FERMCovCollector
# ======================================================================


class TestFERMCovCollectorBasic:
    def test_initial_state(self):
        cov = FERMCovCollector()
        assert cov.blocks_executed == 0
        assert cov.bitmap.count_edges() == 0

    def test_program_edges(self):
        cov = FERMCovCollector()
        cov.on_block(0x1000, in_interrupt=False)
        cov.on_block(0x2000, in_interrupt=False)
        cov.on_block(0x3000, in_interrupt=False)
        assert cov.blocks_executed == 3
        assert cov.bitmap.count_edges() == 3  # 0->1000, 1000->2000, 2000->3000

    def test_interrupt_edges_separate(self):
        """Interrupt edges use a separate last_block, so they don't
        cross-contaminate program edges."""
        cov = FERMCovCollector()
        # Program: A -> B
        cov.on_block(0x1000, in_interrupt=False)
        cov.on_block(0x2000, in_interrupt=False)
        # Interrupt: ISR_X -> ISR_Y
        cov.on_block(0x8000, in_interrupt=True)
        cov.on_block(0x8100, in_interrupt=True)
        # Back to program: B -> C (NOT ISR_Y -> C)
        cov.on_block(0x3000, in_interrupt=False)
        assert cov.blocks_executed == 5

    def test_interrupt_does_not_affect_program_chain(self):
        """The same program sequence should produce the same program edges
        regardless of whether an interrupt fires in between."""
        # Run WITHOUT interrupt
        cov_no_int = FERMCovCollector()
        cov_no_int.on_block(0x1000, in_interrupt=False)
        cov_no_int.on_block(0x2000, in_interrupt=False)
        cov_no_int.on_block(0x3000, in_interrupt=False)

        # Run WITH interrupt between block 2 and 3
        cov_with_int = FERMCovCollector()
        cov_with_int.on_block(0x1000, in_interrupt=False)
        cov_with_int.on_block(0x2000, in_interrupt=False)
        cov_with_int.on_block(0x8000, in_interrupt=True)  # ISR
        cov_with_int.on_block(0x8100, in_interrupt=True)  # ISR
        cov_with_int.on_block(0x3000, in_interrupt=False)

        # The program edges (0->1000, 1000->2000, 2000->3000) should be
        # identical. The interrupt-inclusive run adds extra ISR edges but
        # the program-channel edges are the same.
        # We verify by checking that the program-only run's bitmap is a
        # subset of the interrupt run's bitmap.
        no_int_bytes = cov_no_int.bitmap.to_bytes()
        with_int_bytes = cov_with_int.bitmap.to_bytes()
        for i in range(len(no_int_bytes)):
            if no_int_bytes[i] != 0:
                assert with_int_bytes[i] != 0, (
                    f"Program edge at bucket {i} missing in interrupt run"
                )

    def test_reset_clears_everything(self):
        cov = FERMCovCollector()
        cov.on_block(0x1000, in_interrupt=False)
        cov.on_block(0x2000, in_interrupt=True)
        cov.reset()
        assert cov.blocks_executed == 0
        assert cov.bitmap.count_edges() == 0

    def test_interrupt_chain_resets_on_return_to_program(self):
        """When returning to program context, last_int_block resets to 0,
        so the next interrupt entry always starts from 0."""
        cov = FERMCovCollector()
        cov.on_block(0x1000, in_interrupt=False)
        # First interrupt
        cov.on_block(0x8000, in_interrupt=True)
        # Return to program
        cov.on_block(0x2000, in_interrupt=False)
        # Second interrupt at the SAME address should produce
        # the same edge (0 -> 0x8000) because last_int_block was reset
        edges_before = cov.bitmap.count_edges()
        cov.on_block(0x8000, in_interrupt=True)
        edges_after = cov.bitmap.count_edges()
        # The edge 0->0x8000 already exists, so no new edge
        assert edges_after == edges_before


class TestFERMCovSameSequenceDifferentTiming:
    """Same block sequence with different interrupt timing should produce
    the same program coverage (FERMCov's core guarantee)."""

    def test_timing_invariance(self):
        blocks = [0x1000, 0x2000, 0x3000, 0x4000]
        isr_addr = 0xF000

        # Run 1: interrupt after block 1
        cov1 = FERMCovCollector()
        cov1.on_block(blocks[0], in_interrupt=False)
        cov1.on_block(isr_addr, in_interrupt=True)
        for b in blocks[1:]:
            cov1.on_block(b, in_interrupt=False)

        # Run 2: interrupt after block 3
        cov2 = FERMCovCollector()
        for b in blocks[:3]:
            cov2.on_block(b, in_interrupt=False)
        cov2.on_block(isr_addr, in_interrupt=True)
        cov2.on_block(blocks[3], in_interrupt=False)

        # Program edges should be identical: we check that every
        # program-only edge present in run 1 is also in run 2 and vice versa.
        # To isolate program edges, run without interrupts as reference.
        cov_ref = FERMCovCollector()
        for b in blocks:
            cov_ref.on_block(b, in_interrupt=False)

        ref_bytes = cov_ref.bitmap.to_bytes()
        b1 = cov1.bitmap.to_bytes()
        b2 = cov2.bitmap.to_bytes()

        # All program edges from ref must be in both runs
        for i in range(len(ref_bytes)):
            if ref_bytes[i] != 0:
                assert b1[i] != 0, f"Run 1 missing program edge at bucket {i}"
                assert b2[i] != 0, f"Run 2 missing program edge at bucket {i}"
