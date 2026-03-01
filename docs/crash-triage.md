# Crash Triage

RTOSploit's crash triage pipeline classifies crashes by exploitability, then minimizes the inputs needed to reproduce them. It operates on the JSON crash files produced by the fuzzer.

---

## Crash File Format

The fuzzer writes one JSON file per unique crash to the `crashes/` output directory:

```json
{
  "crash_id": "crash_001",
  "input": "base64-encoded-input-bytes",
  "fault_type": "SEGFAULT",
  "pc": "0x00001248",
  "lr": "0x00000f9c",
  "sp": "0x20001fc0",
  "fault_address": "0x00000008",
  "registers": {
    "r0": "0x00000000",
    "r1": "0x20001800",
    "r2": "0x00000040",
    "r3": "0x00000000"
  },
  "cfsr": "0x00000082",
  "timestamp": "2024-01-15T10:23:45Z"
}
```

---

## Exploitability Classification

The `ExploitabilityClassifier` analyses each crash using ARM Cortex-M fault registers:

### CFSR (Configurable Fault Status Register)

The CFSR at `0xE000ED28` combines three sub-registers:

| Bits | Sub-register | Meaning |
|------|-------------|---------|
| 7:0 | MMFSR | MemManage Fault Status |
| 15:8 | BFSR | BusFault Status |
| 31:16 | UFSR | UsageFault Status |

Key CFSR flags checked during triage:

| Flag | Bit | Significance |
|------|-----|-------------|
| `MMARVALID` | 7 | MemManage address register holds a valid address |
| `DACCVIOL` | 1 | Data access violation — attacker influenced the fault address |
| `IACCVIOL` | 0 | Instruction access violation — potential code execution |
| `BFARVALID` | 15 | BusFault address register valid |
| `PRECISERR` | 9 | Precise bus fault — fault address is accurate |
| `IBUSERR` | 8 | Instruction bus error — execution reached attacker memory |
| `UNDEFINSTR` | 16 | Undefined instruction — possible shellcode execution attempt |
| `INVPC` | 18 | Invalid PC load — EXC_RETURN corruption |
| `DIVBYZERO` | 25 | Divide by zero — controlled arithmetic |

---

## Classification Logic

```
PC in attacker-controlled range?
  → EXPLOITABLE

CFSR.INVPC set?  (EXC_RETURN corruption)
  → EXPLOITABLE

Fault address == NULL (0x00000000)?
  → PROBABLY_NOT_EXPLOITABLE (null dereference)

CFSR.DACCVIOL + MMARVALID + non-null fault address?
  → PROBABLY_EXPLOITABLE (write-what-where candidate)

CFSR.IACCVIOL or IBUSERR?
  → PROBABLY_EXPLOITABLE (execution reached unexpected memory)

CFSR.UNDEFINSTR?
  → PROBABLY_EXPLOITABLE (shellcode may have run)

Fault in read-only/fixed address?
  → PROBABLY_NOT_EXPLOITABLE

Default:
  → UNKNOWN
```

---

## Input Minimization

After classification, the `CrashMinimizer` reduces crash inputs using binary search:

1. Start with the full crash input (N bytes)
2. Try removing the second half → does the crash still reproduce?
3. If yes, keep removing; if no, restore and try the first quarter, etc.
4. Continue until the input cannot be reduced further

The minimized input:
- Is smaller and easier to analyse manually
- Reveals which bytes actually trigger the vulnerability
- Is stored alongside the original crash

---

## Running Triage

```bash
# Basic — text output to terminal
rtosploit triage \
  --crash-dir ./fuzz-out/crashes \
  --firmware firmware.bin \
  --machine mps2-an385

# SARIF output for CI integration
rtosploit triage \
  --crash-dir ./crashes \
  --firmware firmware.bin \
  --format sarif \
  --output triage.sarif.json

# Skip minimization for speed
rtosploit triage \
  --crash-dir ./crashes \
  --firmware firmware.bin \
  --minimize false

# JSON for scripting
rtosploit --json triage --crash-dir ./crashes --firmware firmware.bin
```

---

## Output Format

### Text (default)

```
Triage Results
──────────────────────────────────────────────────────────────
 #  Crash ID     Class                    Orig   Minimized
 1  crash_003    EXPLOITABLE              1024   64 bytes
 2  crash_001    PROBABLY_EXPLOITABLE     512    128 bytes
 3  crash_007    UNKNOWN                  256    —
──────────────────────────────────────────────────────────────
3 crash(es) triaged. 1 EXPLOITABLE, 1 PROBABLY_EXPLOITABLE, 1 UNKNOWN.
```

### JSON

```json
[
  {
    "crash_id": "crash_003",
    "original_size": 1024,
    "minimized_size": 64,
    "triage_result": {
      "exploitability": "EXPLOITABLE",
      "reasons": ["PC in attacker-controlled range", "CFSR.INVPC set"],
      "cfsr_flags": ["INVPC", "DACCVIOL"],
      "fault_type": "MEMMANAGE",
      "pc_control": true,
      "sp_control": false
    },
    "crash_data": {
      "pc": "0x41414149",
      "fault_address": "0x00000008"
    }
  }
]
```

---

## Exploitability Classes

| Class | Description | Priority |
|-------|-------------|---------|
| `EXPLOITABLE` | Strong evidence of attacker control over PC or EXC_RETURN | Critical |
| `PROBABLY_EXPLOITABLE` | Partial control, write-what-where, or execution reaching attacker memory | High |
| `PROBABLY_NOT_EXPLOITABLE` | Crash without memory influence (null dereference, fixed address) | Low |
| `UNKNOWN` | Insufficient fault data to classify | Medium |

Triage results are sorted with `EXPLOITABLE` first so the most critical items are always at the top of the output.

---

## Integrating Triage into the Full Pipeline

The `scan` command automatically runs triage after fuzzing. You can also chain commands manually:

```bash
# Fuzz for 10 minutes
rtosploit fuzz --firmware fw.bin --machine mps2-an385 --timeout 600 --output fuzz-out

# Triage all crashes
rtosploit triage --crash-dir fuzz-out/crashes --firmware fw.bin --format sarif --output triage.sarif

# Generate report from triage output
rtosploit report --input-dir fuzz-out --output reports --format both
```
