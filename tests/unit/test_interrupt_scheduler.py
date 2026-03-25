"""Tests for rtosploit.peripherals.interrupt_scheduler."""

from __future__ import annotations


from rtosploit.peripherals.interrupt_scheduler import InterruptScheduler


class TestInterruptSchedulerBasic:
    def test_construction(self):
        sched = InterruptScheduler(irq_list=[1, 2, 3], interval=100)
        assert sched.stats["blocks_counted"] == 0
        assert sched.stats["interrupts_fired"] == 0

    def test_empty_irq_list(self):
        sched = InterruptScheduler(irq_list=[], interval=10)
        for _ in range(100):
            assert sched.on_block() is None

    def test_empty_irq_list_wfi(self):
        sched = InterruptScheduler(irq_list=[], interval=10)
        assert sched.on_wfi() is None


class TestInterruptSchedulerRoundRobin:
    def test_fires_at_interval(self):
        sched = InterruptScheduler(irq_list=[5, 10, 15], interval=3)
        results = []
        for _ in range(12):
            r = sched.on_block()
            if r is not None:
                results.append(r)
        # Should fire at blocks 3, 6, 9, 12
        assert len(results) == 4

    def test_round_robin_order(self):
        sched = InterruptScheduler(irq_list=[5, 10, 15], interval=2)
        results = []
        for _ in range(12):
            r = sched.on_block()
            if r is not None:
                results.append(r)
        # Fires at blocks 2, 4, 6, 8, 10, 12 -> 6 firings
        # Round-robin: 5, 10, 15, 5, 10, 15
        assert results == [5, 10, 15, 5, 10, 15]

    def test_no_fire_before_interval(self):
        sched = InterruptScheduler(irq_list=[1], interval=5)
        for _ in range(4):
            assert sched.on_block() is None
        # 5th block triggers
        assert sched.on_block() == 1

    def test_single_irq_always_same(self):
        sched = InterruptScheduler(irq_list=[42], interval=1)
        for _ in range(5):
            assert sched.on_block() == 42


class TestInterruptSchedulerWfi:
    def test_wfi_always_fires(self):
        sched = InterruptScheduler(irq_list=[7, 8], interval=1000)
        # Even though interval is huge, WFI fires immediately
        assert sched.on_wfi() == 7
        assert sched.on_wfi() == 8
        assert sched.on_wfi() == 7  # wraps around

    def test_wfi_advances_round_robin(self):
        sched = InterruptScheduler(irq_list=[1, 2, 3], interval=1000)
        sched.on_wfi()  # fires 1
        sched.on_wfi()  # fires 2
        sched.on_wfi()  # fires 3
        assert sched.stats["interrupts_fired"] == 3


class TestInterruptSchedulerReset:
    def test_reset_clears_state(self):
        sched = InterruptScheduler(irq_list=[1, 2], interval=2)
        # Fire some interrupts
        for _ in range(6):
            sched.on_block()
        assert sched.stats["interrupts_fired"] > 0

        sched.reset()
        assert sched.stats["blocks_counted"] == 0
        assert sched.stats["interrupts_fired"] == 0

    def test_reset_restarts_round_robin(self):
        sched = InterruptScheduler(irq_list=[10, 20, 30], interval=1)
        sched.on_block()  # fires 10
        sched.on_block()  # fires 20
        sched.reset()
        # After reset, should start from 10 again
        assert sched.on_block() == 10


class TestInterruptSchedulerStats:
    def test_stats_keys(self):
        sched = InterruptScheduler(irq_list=[1], interval=1)
        stats = sched.stats
        assert "blocks_counted" in stats
        assert "interrupts_fired" in stats
        assert "current_irq" in stats

    def test_stats_after_activity(self):
        sched = InterruptScheduler(irq_list=[5, 10], interval=1)
        sched.on_block()  # fires 5
        sched.on_block()  # fires 10
        stats = sched.stats
        assert stats["blocks_counted"] == 2
        assert stats["interrupts_fired"] == 2

    def test_empty_irq_list_current_irq(self):
        sched = InterruptScheduler(irq_list=[], interval=1)
        assert sched.stats["current_irq"] == -1
