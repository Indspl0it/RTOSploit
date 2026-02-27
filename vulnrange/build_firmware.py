#!/usr/bin/env python3
"""
build_firmware.py - Generate synthetic ARM Cortex-M firmware binaries for VulnRange labs.

Each binary has:
  - Valid ARM Cortex-M vector table (boots in QEMU mps2-an385)
  - Thumb2 reset handler that sets up MSP and enters infinite loop
  - RTOS-specific identification strings
  - Vulnerable code patterns/mock data areas for exploit module validation

Usage:
    python vulnrange/build_firmware.py
"""
import struct
import os
from pathlib import Path

FIRMWARE_SIZE = 4096
FLASH_BASE = 0x00000000
SRAM_BASE = 0x20000000
INITIAL_SP = 0x20008000

# MPS2-AN385 flash starts at 0x00000000
# Vector table occupies 0x00-0x3F (16 vectors * 4 bytes)
# Code starts at 0x40
CODE_OFFSET = 0x40

# Strings section starts after code
STRINGS_OFFSET = 0x100

# Data/mock buffer area
DATA_OFFSET = 0x800

SCRIPT_DIR = Path(__file__).parent


def build_vector_table(reset_addr: int) -> bytes:
    """Build 16-entry Cortex-M vector table."""
    thumb_addr = reset_addr | 1  # Set Thumb bit
    vectors = [
        INITIAL_SP,     # 0x00: Initial SP
        thumb_addr,     # 0x04: Reset
        thumb_addr,     # 0x08: NMI
        thumb_addr,     # 0x0C: HardFault
        thumb_addr,     # 0x10: MemManage
        thumb_addr,     # 0x14: BusFault
        thumb_addr,     # 0x18: UsageFault
        0,              # 0x1C: Reserved
        0,              # 0x20: Reserved
        0,              # 0x24: Reserved
        0,              # 0x28: Reserved
        thumb_addr,     # 0x2C: SVCall
        thumb_addr,     # 0x30: DebugMon
        0,              # 0x34: Reserved
        thumb_addr,     # 0x38: PendSV
        thumb_addr,     # 0x3C: SysTick
    ]
    return struct.pack("<" + "I" * 16, *vectors)


def build_reset_handler() -> bytes:
    """
    Build minimal Thumb2 reset handler.

    Instructions:
        LDR R0, [PC, #8]    ; Load SP value from literal pool
        MSR MSP, R0          ; Set Main Stack Pointer
        B .                  ; Infinite loop

    Literal pool:
        .word 0x20008000     ; SP value
    """
    code = bytearray()

    # LDR R0, [PC, #8]  ->  encoding: 0x4802 (LDR R0, [PC, #8])
    # PC is current instruction + 4 (pipeline), #8 means 2 words ahead
    # Actually for Thumb: LDR Rt, [PC, #imm8*4]
    # We want to load from PC+8 relative to this instruction
    # LDR R0, [PC, #4] -> 0x4801 (loads from PC+4, which is 2 halfwords after current PC+4)
    # Let's just use the direct approach:

    # MOV R0, #0x2000 (upper)  +  MOVT R0, #0x8000 (lower won't work this way)
    # Simpler: use MOVW/MOVT to load 0x20008000 into R0

    # MOVW R0, #0x8000  -> 0xF248 0x0000  (Thumb2 MOVW)
    # Encoding: MOVW Rd, #imm16
    # imm16 = 0x8000, Rd = R0
    # 11110 i 10 0100 imm4 | 0 imm3 Rd imm8
    # imm16 = 0x8000 -> imm4=1000b=8, imm3=000, imm8=00000000, i=0
    # Wait, let me just encode directly:
    # MOVW R0, #0x8000
    # = 0xF248 0x0000
    code += bytes([0x48, 0xF2, 0x00, 0x00])  # MOVW R0, #0x8000

    # MOVT R0, #0x2000
    # = 0xF6C2 0x0000? No...
    # MOVT Rd, #imm16: 11110 i 10 1100 imm4 | 0 imm3 Rd imm8
    # imm16 = 0x2000 -> imm4=0010b=2, i=0, imm3=000, imm8=00000000
    code += bytes([0xC2, 0xF2, 0x00, 0x00])  # MOVT R0, #0x2000

    # MSR MSP, R0
    # Encoding: 11110 0 11 100 0 Rn | 10 0 0 1 000 SYSm
    # Rn=R0, SYSm=MSP(8)
    code += bytes([0x80, 0xF3, 0x08, 0x88])  # MSR MSP, R0

    # ISB (instruction sync barrier)
    code += bytes([0xBF, 0xF3, 0x6F, 0x8F])  # ISB SY

    # B . (infinite loop) - Thumb encoding: 0xE7FE
    code += bytes([0xFE, 0xE7])               # B .

    return bytes(code)


def build_xport_raise_privilege() -> bytes:
    """
    Build the actual xPortRaisePrivilege function bytes.
    This is the vulnerable function from CVE-2021-43997.

        MRS R0, CONTROL
        MOVS R0, #0
        MSR CONTROL, R0
        ISB
        BX LR
    """
    code = bytearray()
    # MRS R0, CONTROL  (CONTROL = SYSm 0x14)
    code += bytes([0xEF, 0xF3, 0x14, 0x80])  # MRS R0, CONTROL
    # MOVS R0, #0
    code += bytes([0x00, 0x20])               # MOVS R0, #0
    # MSR CONTROL, R0
    code += bytes([0x80, 0xF3, 0x14, 0x88])   # MSR CONTROL, R0  (but this is wrong encoding for 0x14)
    # Actually: MSR CONTROL, R0 -> 0x8x F3 14 8x
    # Let me use proper encoding:
    # MSR spec_reg, Rn: 11110 0 11 100 0 Rn | 10 0 0 SYSm[7:0]
    # Rn=R0(0000), SYSm=CONTROL(0x14=20)
    # First halfword: 1111 0011 1000 0000 = 0xF380
    # Second halfword: 1000 1000 0001 0100 = 0x8814
    # In little-endian bytes: 80 F3 14 88
    # That's what we have. Good.

    # ISB
    code += bytes([0xBF, 0xF3, 0x6F, 0x8F])  # ISB SY
    # BX LR
    code += bytes([0x70, 0x47])               # BX LR
    return bytes(code)


def build_msr_control_gadget() -> bytes:
    """
    Build MSR CONTROL, R0; BX LR gadget for ROP chain discovery.
    This is what CVE-2024-28115 exploit searches for.
    """
    code = bytearray()
    # MRS R0, CONTROL
    code += bytes([0xEF, 0xF3, 0x14, 0x80])  # MRS R0, CONTROL
    # BIC R0, R0, #1 (clear nPRIV bit)
    code += bytes([0x20, 0xF0, 0x01, 0x00])   # BIC R0, R0, #1
    # MSR CONTROL, R0
    code += bytes([0x80, 0xF3, 0x14, 0x88])   # MSR CONTROL, R0
    # BX LR
    code += bytes([0x70, 0x47])               # BX LR
    return bytes(code)


def place_strings(buf: bytearray, offset: int, strings: list[bytes]) -> int:
    """Place null-terminated strings sequentially at offset. Returns next free offset."""
    pos = offset
    for s in strings:
        data = s + b"\x00"
        buf[pos:pos + len(data)] = data
        pos += len(data)
    # Align to 4 bytes
    while pos % 4 != 0:
        pos += 1
    return pos


def build_firmware(name: str, strings: list[bytes], extra_code: bytes = b"",
                   extra_code_offset: int = 0, mock_data: bytes = b"",
                   mock_data_offset: int = DATA_OFFSET) -> bytes:
    """Build a complete firmware binary."""
    buf = bytearray(b"\xFF" * FIRMWARE_SIZE)

    # Reset handler code
    reset_code = build_reset_handler()

    # Vector table (reset points to CODE_OFFSET)
    reset_addr = FLASH_BASE + CODE_OFFSET
    vt = build_vector_table(reset_addr)
    buf[0:len(vt)] = vt

    # Place reset handler code at CODE_OFFSET
    buf[CODE_OFFSET:CODE_OFFSET + len(reset_code)] = reset_code

    # Place extra code (e.g., vulnerable function bytes) after reset handler
    if extra_code:
        ec_offset = extra_code_offset if extra_code_offset else (CODE_OFFSET + len(reset_code) + 4)
        # Align to 4
        ec_offset = (ec_offset + 3) & ~3
        buf[ec_offset:ec_offset + len(extra_code)] = extra_code

    # Place identification strings
    place_strings(buf, STRINGS_OFFSET, strings)

    # Place mock data area
    if mock_data:
        buf[mock_data_offset:mock_data_offset + len(mock_data)] = mock_data

    return bytes(buf)


def build_cve_2018_16525() -> bytes:
    """CVE-2018-16525: FreeRTOS+TCP DNS parsing heap overflow."""
    strings = [
        b"FreeRTOS",
        b"V10.0.1",
        b"FreeRTOS Kernel V10.0.1",
        b"FreeRTOS+TCP",
        b"DNS",
        b"prvParseDNSReply",
        b"configDNS_REPLY_MAX_NAME_LEN",
        b"pvPortMalloc",
        b"vPortFree",
        b"BlockLink_t",
        b"xNetworkBufferDescriptor_t",
    ]

    # Mock DNS response buffer area (simulates heap with BlockLink_t)
    # BlockLink_t: { pxNextFreeBlock (4 bytes), xBlockSize (4 bytes) }
    mock_dns_buf = bytearray(256)
    # Fake heap block header before the DNS buffer
    struct.pack_into("<II", mock_dns_buf, 0, 0x20001100, 64)  # pxNext, size
    # DNS name buffer starts at offset 8
    mock_dns_buf[8:8+12] = b"example.com\x00"
    # Another block header after the buffer (adjacent - overflow target)
    struct.pack_into("<II", mock_dns_buf, 72, 0x20001200, 128)  # pxNext, size

    return build_firmware(
        name="CVE-2018-16525",
        strings=strings,
        mock_data=bytes(mock_dns_buf),
    )


def build_cve_2021_43997() -> bytes:
    """CVE-2021-43997: FreeRTOS-MPU xPortRaisePrivilege bypass."""
    strings = [
        b"FreeRTOS",
        b"V10.4.3",
        b"FreeRTOS Kernel V10.4.3",
        b"xPortRaisePrivilege",
        b"MPU_ENABLED",
        b"configENABLE_MPU",
        b"CONTROL",
        b"portmacro.h",
        b"vPortSVCHandler",
        b"prvSetupMPU",
    ]

    # Place the actual xPortRaisePrivilege function at a known offset
    vuln_func = build_xport_raise_privilege()

    return build_firmware(
        name="CVE-2021-43997",
        strings=strings,
        extra_code=vuln_func,
        extra_code_offset=0x60,  # Known address: 0x00000060
    )


def build_cve_2024_28115() -> bytes:
    """CVE-2024-28115: FreeRTOS-MPU stack overflow ROP."""
    strings = [
        b"FreeRTOS",
        b"V10.6.0",
        b"FreeRTOS Kernel V10.6.0",
        b"MPU_ENABLED",
        b"configENABLE_MPU",
        b"configCHECK_FOR_STACK_OVERFLOW",
        b"vPortSVCHandler",
        b"MSR CONTROL",
        b"xPortRaisePrivilege",
        b"prvRestoreContextOfFirstTask",
    ]

    # Place an MSR CONTROL gadget at a known address for ROP gadget finder
    gadget = build_msr_control_gadget()

    # Mock stack overflow buffer in data area
    # Simulates a task stack with exception frame at the bottom
    mock_stack = bytearray(256)
    # Fill with pattern (like a real stack with local vars)
    for i in range(0, 128, 4):
        struct.pack_into("<I", mock_stack, i, 0xDEADBEEF)
    # Exception frame at offset 128
    # R0, R1, R2, R3, R12, LR(EXC_RETURN), PC, xPSR
    exc_frame = struct.pack("<IIIIIIII",
        0, 0, 0, 0, 0,
        0xFFFFFFFD,   # EXC_RETURN (Thread mode, PSP)
        0x00000041,   # PC (some function)
        0x01000000,   # xPSR (Thumb bit)
    )
    mock_stack[128:128+32] = exc_frame

    return build_firmware(
        name="CVE-2024-28115",
        strings=strings,
        extra_code=gadget,
        extra_code_offset=0x60,
        mock_data=bytes(mock_stack),
    )


def build_cve_2025_5688() -> bytes:
    """CVE-2025-5688: FreeRTOS+TCP LLMNR overflow."""
    strings = [
        b"FreeRTOS",
        b"V10.5.1",
        b"FreeRTOS Kernel V10.5.1",
        b"FreeRTOS+TCP",
        b"LLMNR",
        b"prvParseLLMNRReply",
        b"ipconfigUSE_LLMNR",
        b"pvPortMalloc",
        b"vPortFree",
        b"xNetworkBufferDescriptor_t",
        b"BlockLink_t",
    ]

    # Mock LLMNR response buffer with heap metadata
    mock_llmnr_buf = bytearray(256)
    # Heap block header
    struct.pack_into("<II", mock_llmnr_buf, 0, 0x20002100, 64)
    # LLMNR name buffer
    mock_llmnr_buf[8:8+8] = b"rtoslab\x00"
    # Adjacent heap block (overflow target)
    struct.pack_into("<II", mock_llmnr_buf, 72, 0x20002200, 128)

    return build_firmware(
        name="CVE-2025-5688",
        strings=strings,
        mock_data=bytes(mock_llmnr_buf),
    )


def build_kom_threadx() -> bytes:
    """KOM-ThreadX: ThreadX kernel object manipulation."""
    strings = [
        b"ThreadX",
        b"V6.3.0",
        b"Azure RTOS ThreadX V6.3.0",
        b"_tx_thread_create",
        b"_tx_timer_create",
        b"_tx_thread_resume",
        b"_tx_thread_suspend",
        b"TX_THREAD",
        b"TX_TIMER",
        b"tx_thread_id",
        b"THRD",
    ]

    # Mock thread control block (TX_THREAD) in data area
    # This simulates a real TCB that the KOM exploit would reference
    mock_tcb = bytearray(256)
    TX_THREAD_ID_VALUE = 0x54485244  # "THRD"
    struct.pack_into("<I", mock_tcb, 0x00, TX_THREAD_ID_VALUE)    # tx_thread_id
    struct.pack_into("<I", mock_tcb, 0x04, DATA_OFFSET + 0xF0)    # tx_thread_name ptr
    struct.pack_into("<I", mock_tcb, 0x08, SRAM_BASE + 0x4000)    # tx_thread_stack_ptr
    struct.pack_into("<I", mock_tcb, 0x0C, SRAM_BASE + 0x3C00)    # tx_thread_stack_start
    struct.pack_into("<I", mock_tcb, 0x10, SRAM_BASE + 0x4000)    # tx_thread_stack_end
    struct.pack_into("<I", mock_tcb, 0x14, 0x400)                  # tx_thread_stack_size
    struct.pack_into("<I", mock_tcb, 0x18, 5)                      # tx_thread_priority
    struct.pack_into("<I", mock_tcb, 0x48, 0)                      # tx_thread_state (TX_READY)
    # Name at offset 0xF0
    mock_tcb[0xF0:0xF0+9] = b"main_thd\x00"

    return build_firmware(
        name="KOM-ThreadX",
        strings=strings,
        mock_data=bytes(mock_tcb),
    )


def main():
    labs = {
        "CVE-2018-16525": build_cve_2018_16525,
        "CVE-2021-43997": build_cve_2021_43997,
        "CVE-2024-28115": build_cve_2024_28115,
        "CVE-2025-5688":  build_cve_2025_5688,
        "KOM-ThreadX":    build_kom_threadx,
    }

    for lab_name, builder in labs.items():
        firmware = builder()
        assert len(firmware) == FIRMWARE_SIZE, f"{lab_name}: expected {FIRMWARE_SIZE}, got {len(firmware)}"

        out_path = SCRIPT_DIR / lab_name / "firmware.bin"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(firmware)
        print(f"[OK] {lab_name}: {out_path} ({len(firmware)} bytes)")

    print(f"\nAll {len(labs)} firmware binaries generated successfully.")


if __name__ == "__main__":
    main()
