# Writing VulnRange Labs

VulnRange labs are self-contained CVE reproduction challenges. Each lab bundles a vulnerable firmware image, a manifest, progressive hints, and a reference exploit. They are used for training, skill validation, and CTF-style exercises.

---

## Lab Structure

Each lab lives in a directory under `vulnrange/` with this layout:

```
vulnrange/
  CVE-2021-31571/
    manifest.yaml         # Required: metadata, machine config, scoring
    firmware.bin          # Required: vulnerable firmware image
    exploit.py            # Required: reference exploit script
    hints/
      hint-1.txt          # General hint
      hint-2.txt          # Detailed hint
      hint-3.txt          # Near-spoiler
    writeup.md            # Optional: full exploit writeup
    seeds/                # Optional: fuzzing seed corpus
      seed-0001.bin
```

---

## `manifest.yaml` Schema

```yaml
# Required fields
id: CVE-2021-31571
title: "FreeRTOS Heap Buffer Overflow in prvCopyDataToQueue"
rtos: freertos
rtos_versions:
  - "10.3.x"
  - "10.4.0"
  - "10.4.1"
architecture: armv7m
machine: mps2-an385
firmware: firmware.bin
category: heap_corruption
difficulty: intermediate     # beginner | intermediate | advanced | expert
cvss: 8.8
cve_description: >
  A heap buffer overflow in prvCopyDataToQueue allows an attacker to
  corrupt adjacent memory when oversized data is written to a queue
  without proper bounds checking.

# Optional fields
references:
  - "https://nvd.nist.gov/vuln/detail/CVE-2021-31571"
  - "https://www.freertos.org/security"
exploit_script: exploit.py
writeup: writeup.md
hints:
  - hints/hint-1.txt
  - hints/hint-2.txt
  - hints/hint-3.txt
seeds: seeds/
```

---

## Writing the Reference Exploit

The reference exploit script is a standalone Python file that:
1. Launches QEMU with the bundled firmware
2. Delivers the exploit payload
3. Verifies the outcome
4. Exits with code `0` on success, non-zero on failure

```python
#!/usr/bin/env python3
"""
Reference exploit for CVE-2021-31571.
FreeRTOS heap overflow in prvCopyDataToQueue.
"""

import sys
from pathlib import Path

FIRMWARE  = Path(__file__).parent / "firmware.bin"
MACHINE   = "mps2-an385"
PAYLOAD   = b"\x90" * 64 + b"\xfe\xe7"   # NOP sled + infinite loop


def main() -> int:
    from rtosploit.config import RTOSploitConfig
    from rtosploit.emulation.qemu import QEMUInstance

    config = RTOSploitConfig()
    qemu = QEMUInstance(config)

    try:
        qemu.start(
            firmware_path=str(FIRMWARE),
            machine_name=MACHINE,
            gdb=True,
            paused=True,
        )

        from rtosploit.emulation.gdb import GDBStub
        gdb = GDBStub(port=1234)
        gdb.connect()

        # --- Deliver payload ---
        # Write oversized data to trigger the overflow
        gdb.write_memory(0x20001000, PAYLOAD)
        gdb.continue_execution()

        # --- Verify outcome ---
        import time
        time.sleep(1)
        pc = gdb.read_register("pc")

        if pc == 0x20001040:
            print("[+] Exploit succeeded — PC redirected to payload")
            return 0
        else:
            print(f"[-] Exploit failed — PC = 0x{pc:08x}")
            return 1

    except Exception as e:
        print(f"[-] Error: {e}")
        return 2
    finally:
        qemu.stop()


if __name__ == "__main__":
    sys.exit(main())
```

---

## Writing Hints

Hints are plain text files. Write three progressively specific hints:

**`hints/hint-1.txt`** — General guidance:
```
Look at how FreeRTOS queues handle data copy operations.
What happens when the item size does not match the queue's configured item size?
```

**`hints/hint-2.txt`** — More specific:
```
The vulnerability is in prvCopyDataToQueue in queue.c.
When ucQueueType is set to queueOVERWRITE, no size validation occurs before the memcpy.
Try sending an item larger than xItemSize.
```

**`hints/hint-3.txt`** — Near-spoiler:
```
Use xQueueSend with a data buffer of (xItemSize + 64) bytes.
The extra 64 bytes will overflow into the next TCB structure.
Overwrite the pxTopOfStack pointer with the address of your payload at 0x20001040.
```

---

## Writing the Writeup

`writeup.md` documents the complete exploit development process:

```markdown
# CVE-2021-31571 Writeup

## Vulnerability Overview

CVE-2021-31571 is a heap buffer overflow in FreeRTOS's `prvCopyDataToQueue()` function...

## Root Cause Analysis

When `ucQueueType == queueOVERWRITE`, the function skips the size check...

## Exploitation Strategy

### Step 1: Identify the Target Structure

The FreeRTOS TCB (Task Control Block) sits immediately after the queue in the heap...

### Step 2: Craft the Overflow

```python
overflow = b"A" * xItemSize + b"B" * 64
```

### Step 3: Control the PC

By overwriting `pxTopOfStack` in the adjacent TCB...

## Patch Analysis

FreeRTOS fixed this by adding a bounds check:

```c
if( xItemSize <= pxQueue->uxItemSize ) {
    // safe to copy
}
```

## References
- https://nvd.nist.gov/vuln/detail/CVE-2021-31571
```

---

## Testing Your Lab

```bash
# List it
rtosploit vulnrange list

# Start the challenge
rtosploit vulnrange start CVE-2021-31571

# Test hints
rtosploit vulnrange hint CVE-2021-31571 --level 1
rtosploit vulnrange hint CVE-2021-31571 --level 2
rtosploit vulnrange hint CVE-2021-31571 --level 3

# Run the reference exploit
rtosploit vulnrange solve CVE-2021-31571

# Display the writeup
rtosploit vulnrange writeup CVE-2021-31571

# Verify all assets are valid
rtosploit vulnrange verify CVE-2021-31571
```

The `verify` command checks that:
- `manifest.yaml` is valid and all referenced files exist
- `firmware.bin` is a valid firmware binary (ELF, HEX, SREC, or raw)
- `exploit.py` exits with code `0` when run
- All hint files referenced in the manifest are present

---

## Difficulty Guidelines

| Level | Expected Knowledge |
|-------|--------------------|
| `beginner` | Basic RTOS concepts, no exploit dev experience. Guided by detailed hints. |
| `intermediate` | Understands heap internals, basic shellcode. Hints point to the function. |
| `advanced` | Can read disassembly, familiar with ARM calling conventions. Sparse hints. |
| `expert` | Real-world conditions — ASLR simulation, DEP bypass required. Minimal hints. |

---

## Contributing a Lab

1. Create `vulnrange/<CVE-ID>/` with all required files
2. Run `rtosploit vulnrange verify <CVE-ID>` — must pass with no errors
3. Run `rtosploit vulnrange solve <CVE-ID>` — reference exploit must exit `0`
4. Open a pull request with the new directory
