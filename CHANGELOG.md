# Changelog

## [0.1.0] — 2026-02-27

### Added

- Phase 1: Project foundation (Python package, Rust workspace, config)
- Phase 2: Core utilities (FirmwareImage, MemoryMap, disassembly, error handling)
- Phase 3: QEMU emulation engine (QEMUInstance, QMPClient, GDBClient, SnapshotManager)
- Phase 4: SVD Rust crate (parser, stub generator)
- Phase 5: LibAFL fuzzer core (mutations, coverage bitmap, MMIO-aware splitting)
- Phase 5B: Instrumentation bus (13 event types, telemetry, trace writer)
- Phase 6: Crash detection (6-layer: HardFault, watchdog, canary, heap shadow)
- Phase 7: Firmware analysis (RTOS fingerprint, heap detect, MPU check, strings)
- Phase 8: Exploit framework (ExploitModule ABC, ExploitRegistry, ExploitTarget, runner)
- Phase 9: FreeRTOS exploit modules (6 modules, CVE-2021-43997, CVE-2024-28115)
- Phase 10: ThreadX exploit modules (KOM, byte pool, thread entry)
- Phase 11: Zephyr exploit modules (syscall race, BLE overflow, 3 CVE stubs)
- Phase 12+13: Payload generator (ARM Thumb2/RISC-V shellcode, ROP chains, encoders)
- Phase 14: VulnRange CVE lab (5 ranges: FreeRTOS DNS/MPU/ROP/LLMNR, ThreadX KOM)
- Phase 15: CLI interface (7 command groups: emulate/fuzz/exploit/payload/analyze/svd/vulnrange)
- Phase 16: Interactive console (Metasploit-style REPL with prompt_toolkit)

### Security Note

This framework is for authorized security research, CTF challenges, and educational use only.
