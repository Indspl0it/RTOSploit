# RTOSploit

**Offensive security research framework for RTOS-based embedded systems.**

RTOSploit provides emulation-based fuzzing, RTOS exploit modules, and a CVE reproduction
lab for FreeRTOS, ThreadX, and Zephyr targets — all without physical hardware.

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![Rust 1.75+](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://rustlang.org)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-green.svg)](LICENSE)

## Features

- **Emulation** — QEMU 9.x Cortex-M (M3/M4/M33) and RISC-V emulation
- **Fuzzing** — LibAFL-based grey-box fuzzer with MMIO-aware mutation
- **Exploit Modules** — 15+ CVE-based exploit modules for FreeRTOS, ThreadX, Zephyr
- **Payload Generator** — ARM Thumb2 and RISC-V shellcode templates + ROP chain builder
- **VulnRange** — 5 CVE reproduction labs for hands-on practice
- **CLI** — Click-based command-line interface with Rich formatting
- **Console** — Metasploit-style interactive REPL

## Quick Install

```bash
pip install rtosploit
rtosploit --version
```

## Usage

```bash
# Emulate firmware
rtosploit emulate --firmware fw.bin --machine mps2-an385

# List exploit modules
rtosploit exploit list

# Run exploit
rtosploit exploit run freertos/mpu_bypass --firmware fw.bin --machine mps2-an385

# Interactive console
rtosploit console

# CVE reproduction labs
rtosploit vulnrange list
rtosploit vulnrange start CVE-2021-43997
```

## Exploit Modules

| Module | CVE | RTOS | Category | Reliability |
|--------|-----|------|----------|-------------|
| `freertos/heap_overflow` | — | FreeRTOS | heap_corruption | medium |
| `freertos/tcb_overwrite` | — | FreeRTOS | tcb_overwrite | high |
| `freertos/mpu_bypass` | CVE-2021-43997 | FreeRTOS | mpu_bypass | high |
| `freertos/mpu_bypass_rop` | CVE-2024-28115 | FreeRTOS | mpu_bypass | medium |
| `freertos/tcp_stack` | CVE-2018-16525 | FreeRTOS | heap_corruption | medium |
| `freertos/isr_hijack` | — | FreeRTOS | isr_hijack | high |
| `threadx/kom` | — | ThreadX | arbitrary_rw | high |
| `zephyr/syscall_race` | GHSA-3r6j-5mp3-75wr | Zephyr | race_condition | low |
| `zephyr/ble_overflow` | CVE-2024-6259 | Zephyr | heap_corruption | medium |

## VulnRange Labs

| ID | CVE | Difficulty |
|----|-----|------------|
| CVE-2018-16525 | DNS Heap Overflow | Intermediate |
| CVE-2021-43997 | MPU Privilege Escalation | Beginner |
| CVE-2024-28115 | ROP Privilege Escalation | Advanced |
| CVE-2025-5688 | LLMNR Buffer Overflow | Intermediate |
| KOM-ThreadX | Kernel Object Masquerading | Advanced |

## Documentation

- [Installation](docs/installation.md)
- [Quickstart](docs/quickstart.md)
- [Writing Exploits](docs/writing-exploits.md)
- [Architecture](docs/architecture.md)

## License

GPL-3.0-only. See [LICENSE](LICENSE).
