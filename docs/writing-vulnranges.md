# Writing VulnRange Labs

## Overview

VulnRange is RTOSploit's CVE reproduction lab system. Each range packages a
vulnerable firmware image, an exploit script, and metadata into a self-contained
directory that can be launched, exploited, and verified automatically via QEMU.

Ranges serve two purposes: they provide hands-on practice for RTOS exploitation
and they act as regression tests for RTOSploit's exploit tooling.

## Directory Structure

Each range lives under `vulnrange/<CVE-ID>/` with the following layout:

```
vulnrange/CVE-2024-XXXXX/
  manifest.yaml    # Required — range metadata and configuration
  exploit.py       # Required — exploit script (GDB + shellcode)
  firmware.bin     # Required — pre-built vulnerable firmware image
  writeup.md       # Optional — detailed vulnerability writeup
  qemu.yaml        # Optional — QEMU launch configuration overrides
```

The `VulnRangeManager` auto-discovers ranges by scanning `vulnrange/` for
subdirectories containing a `manifest.yaml`.

## manifest.yaml Format

The manifest describes the vulnerability, target environment, and exploit metadata.
All top-level sections are shown below with field descriptions.

```yaml
# --- Identity ---
id: CVE-2024-XXXXX              # Unique range identifier (usually CVE ID)
title: "Short Human-Readable Title"
cve: CVE-2024-XXXXX             # CVE identifier (optional, null if no CVE)
cvss: 7.5                       # CVSS score (optional, float)
category: heap_corruption       # Category slug for grouping
difficulty: intermediate        # One of: beginner, intermediate, advanced
description: >
  Multi-line description of the vulnerability and what the range demonstrates.

# --- Target Environment ---
target:
  rtos: freertos                # RTOS name: freertos, threadx, zephyr
  rtos_version: "10.4.3"       # Affected version string
  arch: armv7m                  # CPU architecture
  machine: mps2-an385           # QEMU machine type
  firmware: firmware.bin         # Path to firmware binary (relative to range dir)

# --- Vulnerability Details ---
vulnerability:
  type: heap_corruption          # Vulnerability class
  component: "FreeRTOS heap_4"   # Affected component/module
  root_cause: "Missing bounds check on xBlockSize field"
  affected_function: pvPortMalloc
  trigger: "Allocate a block larger than the heap region"

# --- Exploit Configuration ---
exploit:
  technique: heap_metadata_overwrite  # Technique name
  reliability: high                   # high, medium, low
  payload: null                       # Path to payload file or null
  script: exploit.py                  # Exploit script filename

# --- Additional Metadata ---
prerequisites:
  - "QEMU mps2-an385 machine"
  - "arm-none-eabi-gdb for debugging"

tags:
  - heap
  - overflow
  - freertos

hints:
  - "First hint (most vague)"
  - "Second hint (more specific)"
  - "Third hint (nearly gives it away)"
```

### Field Reference

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `id` | string | yes | Unique ID, typically the CVE number |
| `title` | string | yes | Short descriptive title |
| `cve` | string | no | CVE identifier or null |
| `cvss` | float | no | CVSS v3 score |
| `category` | string | yes | Grouping slug (e.g. `mpu_bypass`, `heap_corruption`) |
| `difficulty` | string | yes | `beginner`, `intermediate`, or `advanced` |
| `description` | string | no | Multi-line description |
| `target.rtos` | string | yes | `freertos`, `threadx`, or `zephyr` |
| `target.rtos_version` | string | yes | Version string of the vulnerable RTOS |
| `target.arch` | string | yes | CPU arch (e.g. `armv7m`, `armv8m`) |
| `target.machine` | string | yes | QEMU `-machine` value |
| `target.firmware` | string | yes | Firmware binary filename |
| `vulnerability.type` | string | yes | Vulnerability class identifier |
| `vulnerability.component` | string | yes | Affected source component |
| `vulnerability.root_cause` | string | yes | One-line root cause |
| `vulnerability.affected_function` | string | yes | Function where the bug lives |
| `vulnerability.trigger` | string | yes | How to trigger the vulnerability |
| `exploit.technique` | string | yes | Exploitation technique name |
| `exploit.reliability` | string | yes | `high`, `medium`, or `low` |
| `exploit.payload` | string | no | Payload file path or null |
| `exploit.script` | string | yes | Exploit script filename |
| `hints` | list | no | Progressive hints, vague to specific |

## Writing exploit.py

The exploit script connects to the QEMU GDB stub and demonstrates the
vulnerability. Follow this structure:

```python
#!/usr/bin/env python3
"""
RTOSploit Exploit: CVE-2024-XXXXX
Short description of the exploit.

Usage: python exploit.py [gdb_port]
"""
import sys
import socket
import struct
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("CVE-2024-XXXXX")

GDB_HOST = "127.0.0.1"
GDB_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 1235

# Shellcode bytes for the target architecture
SHELLCODE = bytes([
    # ... architecture-specific instructions ...
])

# GDB RSP helpers
def gdb_checksum(data: str) -> str:
    return format(sum(ord(c) for c in data) % 256, "02x")

def gdb_packet(data: str) -> bytes:
    return f"${data}#{gdb_checksum(data)}".encode()

def gdb_send(sock: socket.socket, data: str) -> str:
    sock.sendall(gdb_packet(data))
    return sock.recv(4096).decode(errors="replace")

def run_exploit(host: str, port: int) -> None:
    log.info("Connecting to GDB stub at %s:%d", host, port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5.0)
        s.connect((host, port))

        # 1. Read initial state to confirm vulnerability precondition
        # 2. Inject shellcode or trigger the vulnerable code path
        # 3. Verify exploitation succeeded (register/memory check)

if __name__ == "__main__":
    run_exploit(GDB_HOST, GDB_PORT)
```

Key points:
- Accept `gdb_port` as a CLI argument with a sensible default.
- Use the GDB Remote Serial Protocol (RSP) to interact with QEMU.
- Log each step so `vulnrange verify` can parse success/failure.
- Handle `ConnectionRefusedError` gracefully for analysis-only mode.

## Creating firmware.bin

Build a minimal firmware image with the vulnerable RTOS version. The general
workflow:

1. **Download the vulnerable RTOS source** at the exact affected version.
2. **Configure a minimal application** with the vulnerable feature enabled
   (e.g., `configENABLE_MPU=1` for MPU bypasses, `configUSE_HEAP_SCHEME=4`
   for heap bugs).
3. **Cross-compile** for the target architecture:
   ```bash
   arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -T linker.ld \
       -nostartfiles -o firmware.elf main.c startup.c freertos/*.c
   arm-none-eabi-objcopy -O binary firmware.elf firmware.bin
   ```
4. **Verify** the image boots in QEMU:
   ```bash
   qemu-system-arm -machine mps2-an385 -kernel firmware.bin -nographic -S -gdb tcp::1235
   ```

Keep firmware images small. Only include the code paths needed to reproduce
the vulnerability.

## Writing writeup.md

The writeup is a human-readable explanation of the vulnerability. Include:

- **Summary** -- what the bug is and why it matters.
- **Root Cause Analysis** -- the specific code flaw with file/line references.
- **Exploitation** -- step-by-step walkthrough of the exploit technique.
- **Impact** -- what an attacker gains.
- **Mitigation** -- how the bug was fixed upstream.

This file is shown to users via `rtosploit range writeup <id>`.

## Testing Your Range

Use the built-in verification command to validate your range:

```bash
rtosploit vulnrange verify <CVE-ID>
```

This checks:
- `manifest.yaml` parses without errors
- `firmware.bin` exists and is non-empty
- `exploit.py` is present and executable
- QEMU can boot the firmware (if QEMU is available)

You can also test individual components:

```bash
# Parse the manifest
python -c "from rtosploit.vulnrange.manifest import load_manifest; print(load_manifest('vulnrange/CVE-2024-XXXXX'))"

# Run the exploit in analysis mode (no QEMU)
python vulnrange/CVE-2024-XXXXX/exploit.py

# Boot firmware in QEMU manually
qemu-system-arm -machine mps2-an385 -kernel vulnrange/CVE-2024-XXXXX/firmware.bin -nographic -S -gdb tcp::1235
```

## Example: Creating a New Range

Walk-through for adding a hypothetical FreeRTOS heap overflow range.

### 1. Create the directory

```bash
mkdir vulnrange/CVE-2024-99999
```

### 2. Write manifest.yaml

```yaml
id: CVE-2024-99999
title: "FreeRTOS heap_4 Metadata Corruption"
cve: CVE-2024-99999
cvss: 9.1
category: heap_corruption
difficulty: intermediate
description: >
  A missing size validation in pvPortMalloc allows an attacker to corrupt
  heap metadata, leading to arbitrary write during the next allocation.

target:
  rtos: freertos
  rtos_version: "10.5.0"
  arch: armv7m
  machine: mps2-an385
  firmware: firmware.bin

vulnerability:
  type: heap_corruption
  component: "FreeRTOS portable/MemMang/heap_4.c"
  root_cause: "xBlockSize not validated against xFreeBytesRemaining"
  affected_function: pvPortMalloc
  trigger: "Request allocation with crafted size value"

exploit:
  technique: heap_metadata_overwrite
  reliability: high
  payload: null
  script: exploit.py

prerequisites:
  - "QEMU mps2-an385 machine"
  - "arm-none-eabi-gdb"

tags:
  - heap
  - overflow
  - freertos
  - cve

hints:
  - "Look at how xBlockSize is used before the allocation is fulfilled."
  - "What happens if xBlockSize wraps around due to an integer overflow?"
  - "Corrupt the next free block's xBlockSize to gain an arbitrary write."
```

### 3. Build firmware.bin

Compile a minimal FreeRTOS 10.5.0 app with `heap_4.c` and a task that
performs controllable allocations. Flash the binary as `firmware.bin`.

### 4. Write exploit.py

Connect via GDB RSP, trigger the allocation with a crafted size, then verify
heap metadata corruption by reading the overwritten block header.

### 5. Add writeup.md

Document the root cause, exploitation steps, and upstream fix.

### 6. Verify

```bash
rtosploit vulnrange verify CVE-2024-99999
```

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the PR process.
