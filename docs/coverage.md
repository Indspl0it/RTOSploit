# Coverage Visualization

RTOSploit renders fuzzing coverage as annotated disassembly and HTML heat maps. Coverage data comes from AFL-compatible bitmap files or trace logs produced during fuzzing.

---

## Coverage Data Formats

### AFL-Style Bitmap

The fuzzer writes a 64 KB shared memory bitmap where each byte represents an edge (branch transition) in the program. A non-zero byte means that edge was executed; the byte value indicates approximate hit count.

Path: typically `fuzz-output/coverage.bitmap` or `fuzz-output/bitmap`.

### Trace Log

A trace log is a text file with one address per line representing every instruction executed:

```
0x00001240
0x00001242
0x00001244
0x00001248
0x0000124a
```

Trace logs are more precise than bitmaps (instruction-level vs edge-level) but significantly larger.

---

## Coverage Commands

### Terminal View

Annotated disassembly in the terminal showing which instructions were hit:

```bash
rtosploit coverage view \
  --firmware firmware.bin \
  --bitmap ./fuzz-out/coverage.bitmap \
  --base-address 0x08000000 \
  --max-lines 80
```

Example output:

```
Coverage View — firmware.bin
Base address: 0x08000000
──────────────────────────────────────────────────────────────
0x08001240  ●  push  {r4, r5, r6, lr}         [hit: 4821]
0x08001242  ●  ldr   r4, [r0, #0]             [hit: 4821]
0x08001244  ●  ldr   r5, [r0, #4]             [hit: 4820]
0x08001248  ○  cmp   r4, #0                   [not hit]
0x0800124a  ○  beq.n 0x08001260               [not hit]
0x0800124c  ●  ldrb  r3, [r4, #0]             [hit: 4820]
──────────────────────────────────────────────────────────────
● = hit   ○ = not hit
Coverage: 23.5% (1134/4821 instructions)
```

### HTML Report

Interactive HTML coverage report with syntax highlighting:

```bash
rtosploit coverage view \
  --firmware firmware.bin \
  --bitmap ./bitmap \
  --format html \
  --output coverage.html
```

Features of the HTML report:
- Color-coded by hit count (blue = low, red = hot)
- Click on an address to see register state at that point (if trace data is available)
- Summary panel with total/covered counts and coverage percentage
- Hot spots table sorted by hit count

### Statistics

Numeric summary without disassembly:

```bash
rtosploit coverage stats \
  --firmware firmware.bin \
  --bitmap ./bitmap

# JSON output for scripting
rtosploit --json coverage stats --firmware fw.bin --bitmap ./bitmap
```

JSON output:

```json
{
  "total_instructions": 4821,
  "covered_instructions": 1134,
  "coverage_percent": 23.5,
  "total_edges": 892,
  "covered_edges": 203,
  "edge_coverage_percent": 22.7,
  "hot_spots": [
    { "address": "0x08001240", "function": "prvCopyDataToQueue", "hits": 4821 },
    { "address": "0x08001242", "function": "prvCopyDataToQueue", "hits": 4820 },
    { "address": "0x08001280", "function": "xQueueGenericSend", "hits": 3901 }
  ]
}
```

---

## Coverage in Interactive Mode

In interactive mode, select **View Coverage** from the firmware menu. You will be prompted for:
- Coverage data directory (where `coverage.bitmap` or trace files reside)
- Output format (terminal or HTML)

---

## Improving Coverage

Low coverage means the fuzzer has not explored much of the firmware. Strategies to improve it:

### Provide Seed Inputs

Seeds prime the fuzzer corpus with valid protocol messages or structured inputs that reach deeper code paths:

```bash
rtosploit fuzz \
  --firmware fw.bin \
  --machine mps2-an385 \
  --seeds ./seeds \
  --output ./fuzz-out
```

### Run Longer

Coverage generally increases with time, especially early in a fuzzing campaign:

```bash
rtosploit fuzz --firmware fw.bin --machine mps2-an385 --timeout 7200
```

### Use the Corpus Across Runs

The `corpus/` directory from previous runs can seed future runs:

```bash
# Continue a previous campaign
rtosploit fuzz \
  --firmware fw.bin \
  --machine mps2-an385 \
  --seeds ./previous-fuzz-out/corpus \
  --output ./fuzz-out-2
```

---

## Combining Bitmaps

When running multiple parallel fuzzer instances, combine bitmaps by bitwise OR to get unified coverage:

```bash
# Combine bitmaps (example using Python)
python3 -c "
import sys
bitmaps = [open(f, 'rb').read() for f in sys.argv[1:]]
combined = bytes(max(b[i] for b in bitmaps) for i in range(len(bitmaps[0])))
sys.stdout.buffer.write(combined)
" instance1/bitmap instance2/bitmap instance3/bitmap > combined.bitmap

rtosploit coverage stats --firmware fw.bin --bitmap combined.bitmap
```
