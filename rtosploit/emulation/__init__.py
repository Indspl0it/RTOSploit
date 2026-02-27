"""QEMU-based firmware emulation engine."""

from rtosploit.emulation.machines import MachineConfig, PeripheralConfig, load_machine, list_machines
from rtosploit.emulation.qmp import QMPClient
from rtosploit.emulation.gdb import GDBClient
from rtosploit.emulation.memory import MemoryOps
from rtosploit.emulation.snapshot import SnapshotManager
from rtosploit.emulation.qemu import QEMUInstance

__all__ = [
    "QEMUInstance",
    "QMPClient",
    "GDBClient",
    "MachineConfig",
    "PeripheralConfig",
    "MemoryOps",
    "SnapshotManager",
    "load_machine",
    "list_machines",
]
