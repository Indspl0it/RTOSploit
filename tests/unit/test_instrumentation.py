"""Unit tests for rtosploit.instrumentation (Phase 5B).

Covers:
- classify_cfsr / exception_name helpers
- EventRingBuffer
- InstrumentationBus (subscribe, publish, filtering, sampling, unsubscribe)
- TelemetryCollector (all event handlers)
- TelemetrySnapshot.to_json
- TraceWriter (level filtering, rotation)
- PeripheralResolver
"""

from __future__ import annotations

import json


# ---------------------------------------------------------------------------
# events helpers
# ---------------------------------------------------------------------------

from rtosploit.instrumentation.events import (
    classify_cfsr,
    exception_name,
    TaskSwitchTrigger,
    HeapOpType,
    ExceptionEntryEvent,
    BasicBlockTransitionEvent,
    TaskSwitchEvent,
    HeapOperationEvent,
)
from rtosploit.instrumentation.bus import (
    InstrumentationBus,
    InstrumentationConfig,
    EventRingBuffer,
)
from rtosploit.instrumentation.telemetry import TelemetryCollector, TelemetrySnapshot
from rtosploit.instrumentation.trace_writer import TraceWriter
from rtosploit.instrumentation.peripheral_resolver import PeripheralResolver


# ===========================================================================
# 1-4: classify_cfsr
# ===========================================================================

def test_classify_cfsr_iaccviol():
    """classify_cfsr(0x01) returns ['IACCVIOL']."""
    assert classify_cfsr(0x01) == ["IACCVIOL"]


def test_classify_cfsr_impreciserr():
    """classify_cfsr(0x400) returns ['IMPRECISERR'] (bit 10 = IMPRECISERR)."""
    # Bit  9 (0x200) = PRECISERR
    # Bit 10 (0x400) = IMPRECISERR
    assert classify_cfsr(0x400) == ["IMPRECISERR"]


def test_classify_cfsr_zero():
    """classify_cfsr(0x0) returns []."""
    assert classify_cfsr(0x0) == []


def test_classify_cfsr_divbyzero():
    """classify_cfsr with DIVBYZERO bit (bit 25) returns ['DIVBYZERO']."""
    assert classify_cfsr(1 << 25) == ["DIVBYZERO"]


# ===========================================================================
# 5-7: exception_name
# ===========================================================================

def test_exception_name_hardfault():
    """exception_name(3) returns 'HardFault'."""
    assert exception_name(3) == "HardFault"


def test_exception_name_pendsv():
    """exception_name(14) returns 'PendSV'."""
    assert exception_name(14) == "PendSV"


def test_exception_name_irq():
    """exception_name(20) returns 'IRQ4' (vector 20 = IRQ 20-16=4)."""
    assert exception_name(20) == "IRQ4"


# ===========================================================================
# 8-12: EventRingBuffer
# ===========================================================================

def _make_event(n: int) -> BasicBlockTransitionEvent:
    return BasicBlockTransitionEvent(from_addr=n, to_addr=n + 1)


def test_ring_buffer_stores_and_retrieves():
    """EventRingBuffer stores and retrieves events correctly."""
    buf = EventRingBuffer(size=10)
    e = _make_event(42)
    buf.push(e)
    assert buf.get_all() == [e]


def test_ring_buffer_eviction():
    """With size=3, pushing 5 events keeps only the last 3."""
    buf = EventRingBuffer(size=3)
    events = [_make_event(i) for i in range(5)]
    for e in events:
        buf.push(e)
    assert len(buf) == 3
    assert buf.get_all() == events[-3:]


def test_ring_buffer_get_last():
    """get_last(2) returns the 2 most recent events."""
    buf = EventRingBuffer(size=10)
    events = [_make_event(i) for i in range(5)]
    for e in events:
        buf.push(e)
    last2 = buf.get_last(2)
    assert last2 == events[-2:]


def test_ring_buffer_len():
    """__len__ returns the correct count of stored events."""
    buf = EventRingBuffer(size=10)
    assert len(buf) == 0
    buf.push(_make_event(1))
    buf.push(_make_event(2))
    assert len(buf) == 2


def test_ring_buffer_clear():
    """clear() resets count to 0."""
    buf = EventRingBuffer(size=10)
    for i in range(5):
        buf.push(_make_event(i))
    buf.clear()
    assert len(buf) == 0
    assert buf.get_all() == []


# ===========================================================================
# 13-17: InstrumentationBus
# ===========================================================================

def _default_bus(**kwargs) -> InstrumentationBus:
    cfg = InstrumentationConfig(**kwargs)
    return InstrumentationBus(cfg)


def _exc_event() -> ExceptionEntryEvent:
    return ExceptionEntryEvent(
        vector_num=3,
        return_addr=0x1000,
        fault_addr=0,
        fault_status_register=0,
        hfsr=0,
    )


def test_bus_subscribe_delivers_event():
    """subscribe() + publish() delivers event to subscriber."""
    bus = _default_bus()
    received = []
    bus.subscribe(received.append)
    ev = _exc_event()
    bus.publish(ev)
    assert received == [ev]


def test_bus_filtering_exceptions_disabled():
    """With trace_exceptions=False, ExceptionEntryEvent is not delivered."""
    bus = _default_bus(trace_exceptions=False)
    received = []
    bus.subscribe(received.append)
    bus.publish(_exc_event())
    assert received == []


def test_bus_ring_buffer_on_publish():
    """publish() stores event in the ring buffer."""
    bus = _default_bus()
    ev = _exc_event()
    bus.publish(ev)
    assert ev in bus.get_ring_buffer().get_all()


def test_bus_get_crash_context():
    """get_crash_context(5) returns the last 5 events."""
    bus = _default_bus()
    events = [_exc_event() for _ in range(10)]
    for ev in events:
        bus.publish(ev)
    ctx = bus.get_crash_context(5)
    assert len(ctx) == 5
    assert ctx == events[-5:]


def test_bus_unsubscribe_stops_delivery():
    """unsubscribe() stops event delivery to the callback."""
    bus = _default_bus()
    received = []
    bus.subscribe(received.append)
    bus.publish(_exc_event())
    bus.unsubscribe(received.append)
    bus.publish(_exc_event())
    assert len(received) == 1  # only the first event was delivered


# ===========================================================================
# 18-22: TelemetryCollector
# ===========================================================================

def _make_telemetry() -> TelemetryCollector:
    return TelemetryCollector()


def test_telemetry_heap_malloc():
    """on_event(HeapOperationEvent malloc) increments allocation_count."""
    tc = _make_telemetry()
    ev = HeapOperationEvent(op_type=HeapOpType.MALLOC, address=0x2000, size=64, caller_pc=0x800)
    tc.on_event(ev)
    assert tc.get_snapshot().heap.allocation_count == 1
    assert tc.get_snapshot().heap.current_allocated_bytes == 64


def test_telemetry_heap_free():
    """on_event(HeapOperationEvent free) increments free_count."""
    tc = _make_telemetry()
    # malloc first so we have something to free
    tc.on_event(HeapOperationEvent(op_type=HeapOpType.MALLOC, address=0x2000, size=64, caller_pc=0x800))
    tc.on_event(HeapOperationEvent(op_type=HeapOpType.FREE, address=0x2000, size=0, caller_pc=0x900))
    snap = tc.get_snapshot()
    assert snap.heap.free_count == 1
    assert snap.heap.current_allocated_bytes == 0


def test_telemetry_task_switch():
    """on_event(TaskSwitchEvent) increments switch_count and adds TCBs to tasks_seen."""
    tc = _make_telemetry()
    ev = TaskSwitchEvent(
        from_task_tcb_addr=0x2000,
        to_task_tcb_addr=0x3000,
        trigger=TaskSwitchTrigger.PENDSV,
    )
    tc.on_event(ev)
    snap = tc.get_snapshot()
    assert snap.tasks.switch_count == 1
    assert 0x2000 in snap.tasks.tasks_seen
    assert 0x3000 in snap.tasks.tasks_seen


def test_telemetry_exception_entry():
    """on_event(ExceptionEntryEvent) increments exceptions_triggered."""
    tc = _make_telemetry()
    tc.on_event(_exc_event())
    assert tc.get_snapshot().execution.exceptions_triggered == 1


def test_telemetry_basic_block_transition():
    """on_event(BasicBlockTransitionEvent) updates unique_edges count."""
    tc = _make_telemetry()
    ev1 = BasicBlockTransitionEvent(from_addr=0x100, to_addr=0x200)
    ev2 = BasicBlockTransitionEvent(from_addr=0x200, to_addr=0x300)
    ev_dup = BasicBlockTransitionEvent(from_addr=0x100, to_addr=0x200)
    tc.on_event(ev1)
    tc.on_event(ev2)
    tc.on_event(ev_dup)
    snap = tc.get_snapshot()
    assert snap.execution.unique_edges == 2   # duplicate edge not counted again
    assert snap.execution.basic_blocks_visited == 3  # but bb count still increments


# ===========================================================================
# 23: TelemetrySnapshot.to_json
# ===========================================================================

def test_snapshot_to_json_valid():
    """TelemetrySnapshot.to_json() produces valid JSON with expected keys."""
    snap = TelemetrySnapshot()
    raw = snap.to_json()
    data = json.loads(raw)
    assert "execution" in data
    assert "heap" in data
    assert "interrupts" in data
    assert "tasks" in data
    assert "session_start" in data
    # Spot-check nested keys
    assert "unique_edges" in data["execution"]
    assert "allocation_count" in data["heap"]


# ===========================================================================
# 24-26: TraceWriter
# ===========================================================================

def test_trace_writer_off_writes_nothing(tmp_path):
    """TraceWriter with level='off' writes nothing."""
    log = tmp_path / "trace.log"
    tw = TraceWriter(log_path=log, level="off")
    tw.write(_exc_event())
    tw.close()
    assert not log.exists()


def test_trace_writer_minimal_only_exceptions(tmp_path):
    """TraceWriter with level='minimal' only writes ExceptionEntryEvents."""
    log = tmp_path / "trace.log"
    tw = TraceWriter(log_path=log, level="minimal")
    tw.write(_exc_event())
    tw.write(BasicBlockTransitionEvent(from_addr=0, to_addr=1))
    tw.close()
    content = log.read_text()
    assert "exception_entry" in content
    assert "basic_block_transition" not in content


def test_trace_writer_rotation(tmp_path):
    """TraceWriter rotates the file when it exceeds max_size_bytes."""
    log = tmp_path / "trace.log"
    # 1 KB limit
    tw = TraceWriter(log_path=log, level="verbose", max_size_mb=0)
    # max_size_bytes will be 0, so every write triggers rotation
    # Force a small limit
    tw.max_size_bytes = 50  # 50 bytes

    ev = _exc_event()
    for _ in range(20):
        tw.write(ev)
    tw.close()

    # At least one rotated file should exist
    rotated = list(tmp_path.glob("trace.log.*"))
    assert len(rotated) >= 1


# ===========================================================================
# 27-30: PeripheralResolver
# ===========================================================================

def _make_machine_config():
    """Build a minimal MachineConfig with one peripheral for testing."""
    from rtosploit.emulation.machines import MachineConfig, PeripheralConfig
    mc = MachineConfig(
        name="test",
        qemu_machine="test-machine",
        cpu="cortex-m3",
        architecture="arm",
        memory={},
        peripherals={
            "UART0": PeripheralConfig(name="UART0", base=0x40001000, size=0x1000),
            "SPI1":  PeripheralConfig(name="SPI1",  base=0x40002000, size=0x400),
        },
    )
    return mc


def test_peripheral_resolver_exact_base():
    """resolve(base_addr) returns (name, 0) for an exact base hit."""
    mc = _make_machine_config()
    pr = PeripheralResolver(mc)
    result = pr.resolve(0x40001000)
    assert result == ("UART0", 0)


def test_peripheral_resolver_offset():
    """resolve(base + 4) returns (name, 4) for an offset within the peripheral."""
    mc = _make_machine_config()
    pr = PeripheralResolver(mc)
    result = pr.resolve(0x40001000 + 4)
    assert result == ("UART0", 4)


def test_peripheral_resolver_not_mmio():
    """resolve(non_mmio_addr) returns None."""
    mc = _make_machine_config()
    pr = PeripheralResolver(mc)
    result = pr.resolve(0x20000000)  # SRAM address
    assert result is None


def test_peripheral_resolver_is_mmio_true():
    """is_mmio(addr_inside_peripheral) returns True."""
    mc = _make_machine_config()
    pr = PeripheralResolver(mc)
    assert pr.is_mmio(0x40002100) is True  # inside SPI1 (0x40002000, size=0x400)


def test_peripheral_resolver_is_mmio_false():
    """is_mmio(non_mmio_addr) returns False."""
    mc = _make_machine_config()
    pr = PeripheralResolver(mc)
    assert pr.is_mmio(0x08000000) is False  # Flash


# ===========================================================================
# Additional edge-case tests (bonus coverage)
# ===========================================================================

def test_classify_cfsr_multiple_faults():
    """classify_cfsr with multiple bits set returns all matching fault names."""
    # IACCVIOL (bit 0) | IBUSERR (bit 8)
    result = classify_cfsr(0x0101)
    assert "IACCVIOL" in result
    assert "IBUSERR" in result


def test_ring_buffer_get_last_more_than_stored():
    """get_last(N) with N > stored count returns all stored events."""
    buf = EventRingBuffer(size=10)
    buf.push(_make_event(1))
    buf.push(_make_event(2))
    assert buf.get_last(100) == buf.get_all()


def test_bus_sampling_rate():
    """With sampling_rate=2, only every other event reaches subscribers."""
    bus = _default_bus(sampling_rate=2)
    received = []
    bus.subscribe(received.append)
    for _ in range(10):
        bus.publish(_exc_event())
    # Exactly 5 events should pass (1-in-2 sampling)
    assert len(received) == 5


def test_bus_trace_level_off():
    """With trace_level='off', no events are stored or dispatched."""
    bus = _default_bus(trace_level="off")
    received = []
    bus.subscribe(received.append)
    bus.publish(_exc_event())
    assert received == []
    assert len(bus.get_ring_buffer()) == 0


def test_telemetry_heap_peak():
    """Peak allocated bytes is correctly tracked across alloc/free."""
    tc = _make_telemetry()
    tc.on_event(HeapOperationEvent(op_type=HeapOpType.MALLOC, address=0x2000, size=100, caller_pc=0))
    tc.on_event(HeapOperationEvent(op_type=HeapOpType.MALLOC, address=0x2100, size=200, caller_pc=0))
    tc.on_event(HeapOperationEvent(op_type=HeapOpType.FREE,   address=0x2000, size=0,   caller_pc=0))
    snap = tc.get_snapshot()
    assert snap.heap.peak_allocated_bytes == 300
    assert snap.heap.current_allocated_bytes == 200


def test_trace_writer_standard_level(tmp_path):
    """TraceWriter with level='standard' writes exceptions and task switches but not basic blocks."""
    log = tmp_path / "trace.log"
    tw = TraceWriter(log_path=log, level="standard")
    tw.write(_exc_event())
    tw.write(TaskSwitchEvent(
        from_task_tcb_addr=0x2000,
        to_task_tcb_addr=0x3000,
        trigger=TaskSwitchTrigger.PENDSV,
    ))
    tw.write(BasicBlockTransitionEvent(from_addr=0, to_addr=1))
    tw.close()
    content = log.read_text()
    assert "exception_entry" in content
    assert "task_switch" in content
    assert "basic_block_transition" not in content


def test_bus_reset_stats():
    """reset_stats() clears event count and ring buffer."""
    bus = _default_bus()
    for _ in range(5):
        bus.publish(_exc_event())
    bus.reset_stats()
    assert bus.event_count == 0
    assert len(bus.get_ring_buffer()) == 0


def test_telemetry_reset():
    """TelemetryCollector.reset() discards all accumulated state."""
    tc = _make_telemetry()
    tc.on_event(_exc_event())
    tc.on_event(HeapOperationEvent(op_type=HeapOpType.MALLOC, address=0x2000, size=64, caller_pc=0))
    tc.reset()
    snap = tc.get_snapshot()
    assert snap.execution.exceptions_triggered == 0
    assert snap.heap.allocation_count == 0
