# RTOSploit — Setup & Usage Guide

This guide covers Docker deployment, local installation, QEMU setup, and step-by-step workflows for every major feature. For the full CLI reference (flags, options, output formats), see [README.md](README.md).

---

## Table of Contents

- [Quick Start (Docker)](#quick-start-docker)
- [Quick Start (Local)](#quick-start-local)
- [Installing QEMU](#installing-qemu)
- [Docker Workflows](#docker-workflows)
- [Tool Workflows](#tool-workflows)
- [Configuration](#configuration)
- [Bundled Firmware](#bundled-firmware)
- [Troubleshooting](#troubleshooting)

---

## Quick Start (Docker)

Three commands to get running:

```bash
# 1. Clone the repo
git clone https://github.com/Indspl0it/RTOSploit && cd rtosploit

# 2. Build the image
docker compose build

# 3. Run a scan on bundled firmware
docker compose run --rm rtosploit scan \
  --firmware /rtosploit/vulnrange/downloaded_firmware/freertos-full-demo-mps2-an385.elf \
  --machine mps2-an385 --fuzz-timeout 30 --output /output/first-scan
```

Results are written to the `./output/` directory on your host.

---

## Quick Start (Local)

```bash
# 1. Clone and create a virtualenv
git clone https://github.com/Indspl0it/RTOSploit && cd rtosploit
python3 -m venv .venv
source .venv/bin/activate

# 2. Install RTOSploit (editable)
pip install -e ".[dev]"

# 3. Install QEMU (see section below for your platform)
sudo apt install qemu-system-arm qemu-system-misc   # Debian/Ubuntu

# 4. (Optional) Build the native Rust fuzzer
cargo build --release

# 5. Verify
rtosploit --version
qemu-system-arm --version   # must be 9.0+

# 6. Run interactive mode
rtosploit
```

---

## Installing QEMU

RTOSploit requires QEMU 9.0 or later. The `qemu-system-arm` binary must be in your `PATH`.

### Debian / Ubuntu (apt)

```bash
sudo apt update
sudo apt install -y qemu-system-arm qemu-system-misc gdb-multiarch
```

> **Note:** Ubuntu 24.04 ships QEMU 8.2. If your distro provides an older version, build from source (see below).

### Building QEMU from Source

Use this when your package manager provides QEMU < 9.0.

```bash
# Install build dependencies
sudo apt install -y build-essential ninja-build pkg-config \
  libglib2.0-dev libpixman-1-dev libslirp-dev python3-venv

# Download and extract
QEMU_VERSION=9.2.0
curl -LO https://download.qemu.org/qemu-${QEMU_VERSION}.tar.xz
tar xf qemu-${QEMU_VERSION}.tar.xz
cd qemu-${QEMU_VERSION}

# Configure (ARM + RISC-V targets only — fast build)
./configure \
  --target-list=arm-softmmu,riscv32-softmmu \
  --prefix=/usr/local

# Build and install
make -j$(nproc)
sudo make install

# Verify
qemu-system-arm --version
```

### macOS (Homebrew)

```bash
brew install qemu gdb
```

Homebrew typically ships QEMU 9.x. Verify with `qemu-system-arm --version`.

### Windows (WSL2)

RTOSploit runs inside WSL2. Install a Linux distribution from the Microsoft Store, then follow the Debian/Ubuntu instructions above.

```powershell
# From PowerShell (if WSL2 is not yet installed)
wsl --install -d Ubuntu-24.04
```

Then inside the WSL2 terminal:

```bash
sudo apt update
sudo apt install -y qemu-system-arm qemu-system-misc gdb-multiarch
```

### Verifying the Installation

```bash
# Check version (must be >= 9.0)
qemu-system-arm --version

# Check that the mps2-an385 machine is available
qemu-system-arm -machine help | grep mps2-an385

# Quick boot test with bundled firmware
rtosploit emulate \
  --firmware vulnrange/downloaded_firmware/freertos-full-demo-mps2-an385.elf \
  --machine mps2-an385
```

---

## Docker Workflows

All Docker commands use `docker compose run --rm rtosploit` as the base. This mounts three volumes automatically:

| Container Path | Host Path | Purpose |
|----------------|-----------|---------|
| `/firmware` | `./firmware/` | Mount your firmware files here |
| `/output` | `./output/` | Scan results, crash data, reports |
| `/data` | Named volume | CVE database, fuzzer corpus persistence |

### Building the Image

```bash
# Standard build
docker compose build

# Rebuild from scratch (no cache)
docker compose build --no-cache

# Check the image size
docker images | grep rtosploit
```

### Running Scans with Mounted Firmware

Place your firmware in `./firmware/`, then reference it as `/firmware/<filename>`:

```bash
# Full security scan
docker compose run --rm rtosploit scan \
  --firmware /firmware/my-device.elf \
  --machine mps2-an385 \
  --fuzz-timeout 120 \
  --output /output/my-device-scan

# Static analysis only (no QEMU needed)
docker compose run --rm rtosploit analyze \
  --firmware /firmware/my-device.elf --all
```

### Fuzzing with Persistent Output

```bash
docker compose run --rm rtosploit fuzz \
  --firmware /firmware/my-device.elf \
  --machine mps2-an385 \
  --timeout 600 \
  --output /output/fuzz-results

# Results persist in ./output/fuzz-results/ on your host
ls ./output/fuzz-results/crashes/
```

### GDB Debugging through Docker

Port 1234 is exposed for GDB:

```bash
# Terminal 1: Start emulation with GDB stub
docker compose run --rm --service-ports rtosploit emulate \
  --firmware /firmware/my-device.elf \
  --machine mps2-an385 \
  --gdb --gdb-port 1234

# Terminal 2: Connect GDB from host
gdb-multiarch -ex "target remote localhost:1234" my-device.elf
```

> **Important:** Use `--service-ports` to publish the mapped ports when using `docker compose run`.

### Interactive Mode in Docker

```bash
docker compose run --rm rtosploit
```

This launches the TUI menu system inside the container. Bundled firmware is at `/rtosploit/vulnrange/downloaded_firmware/`.

### Running Tests in Docker

```bash
# Unit tests
docker compose run --rm --entrypoint pytest rtosploit tests/unit/ -v --tb=short

# With coverage
docker compose run --rm --entrypoint pytest rtosploit tests/unit/ --cov=rtosploit
```

### Using Bundled Firmware in Docker

The container includes all VulnRange firmware at `/rtosploit/vulnrange/downloaded_firmware/`:

```bash
# Scan bundled FreeRTOS+TCP demo
docker compose run --rm rtosploit scan \
  --firmware /rtosploit/vulnrange/downloaded_firmware/freertos-tcp-echo-mps2-an385.elf \
  --machine mps2-an385 --fuzz-timeout 60 --output /output/tcp-scan

# Try a VulnRange lab
docker compose run --rm rtosploit vulnrange list
docker compose run --rm rtosploit vulnrange start CVE-2018-16525
```

---

## Tool Workflows

Step-by-step recipes for each major feature. For flag details and output format options, see the [CLI Reference in README.md](README.md#cli-reference).

### Interactive Mode

Launch with no arguments for the guided menu system:

```bash
rtosploit

# Docker equivalent
docker compose run --rm rtosploit
```

The TUI walks you through firmware loading, RTOS detection, and action selection. Use arrow keys to navigate.

### Full Security Scan

Run all phases (fingerprint, CVE check, fuzz, triage, report) in one command:

```bash
rtosploit scan \
  --firmware firmware.elf \
  --machine mps2-an385 \
  --fuzz-timeout 120 \
  --format both \
  --output ./scan-results

# Docker equivalent
docker compose run --rm rtosploit scan \
  --firmware /firmware/firmware.elf \
  --machine mps2-an385 \
  --fuzz-timeout 120 \
  --format both \
  --output /output/scan-results
```

Check the exit code for CI integration: `0` = clean, `1` = findings above threshold, `2` = error.

### Fuzzing

```bash
# Basic 5-minute fuzz session
rtosploit fuzz \
  --firmware firmware.elf \
  --machine mps2-an385 \
  --timeout 300 \
  --output ./fuzz-out

# Parallel fuzzing with 4 jobs
rtosploit fuzz \
  --firmware firmware.elf \
  --machine mps2-an385 \
  --jobs 4 \
  --timeout 3600 \
  --output ./fuzz-out
```

The live dashboard shows executions/sec, crash count, and coverage in real time.

### Firmware Rehosting

Use the `rehost` command to run firmware with HAL peripheral intercepts instead of full QEMU peripheral emulation:

```bash
# Generate a peripheral config from an SVD file first
rtosploit svd generate STM32F407.svd --output ./stubs --mode fuzzer

# Rehost with peripheral intercepts
rtosploit rehost \
  --firmware firmware.elf \
  --machine stm32f4 \
  --peripheral-config ./stubs/peripheral_map.h \
  --timeout 60

# Docker equivalent
docker compose run --rm rtosploit rehost \
  --firmware /firmware/firmware.elf \
  --machine stm32f4 \
  --peripheral-config /firmware/peripheral_map.h \
  --timeout 60
```

### Static Analysis

No QEMU required — works on raw binaries:

```bash
# Run all analyses
rtosploit analyze --firmware firmware.elf --all

# Individual analyses
rtosploit analyze --firmware firmware.elf --detect-rtos
rtosploit analyze --firmware firmware.elf --detect-heap
rtosploit analyze --firmware firmware.elf --detect-mpu
rtosploit analyze --firmware firmware.elf --strings

# JSON output for scripting
rtosploit --json analyze --firmware firmware.elf --all | jq '.rtos'
```

### CVE Scanning

```bash
# Auto-detect RTOS and correlate
rtosploit cve scan --firmware firmware.elf

# Override RTOS/version for targeted search
rtosploit cve scan --firmware firmware.elf --rtos freertos --version "10.4.3"

# Free-text CVE search
rtosploit cve search "heap overflow"
rtosploit cve search CVE-2021-31571

# Update the CVE database from NVD
rtosploit cve update
NVD_API_KEY=your-key rtosploit cve update   # faster with API key
```

### Exploit Console

Metasploit-style interactive console with tab completion:

```bash
rtosploit console

# Docker equivalent
docker compose run --rm rtosploit console
```

Example session:

```
rtosploit> search freertos heap
rtosploit> use freertos/heap_overflow
rtosploit(freertos/heap_overflow)> show options
rtosploit(freertos/heap_overflow)> set firmware ./firmware.elf
rtosploit(freertos/heap_overflow)> set machine mps2-an385
rtosploit(freertos/heap_overflow)> check
rtosploit(freertos/heap_overflow)> exploit
rtosploit(freertos/heap_overflow)> back
rtosploit> exit
```

### Crash Triage

Classify crash exploitability and minimize inputs:

```bash
rtosploit triage \
  --crash-dir ./fuzz-out/crashes \
  --firmware firmware.elf \
  --machine mps2-an385

# SARIF output for CI integration
rtosploit triage \
  --crash-dir ./fuzz-out/crashes \
  --firmware firmware.elf \
  --format sarif \
  --output triage.sarif.json
```

### Report Generation

Generate reports from collected crash and exploit data:

```bash
# Both SARIF and HTML
rtosploit report \
  --input-dir ./scan-results \
  --output ./reports \
  --format both

# SARIF only (for GitHub Code Scanning upload)
rtosploit report \
  --input-dir ./scan-results \
  --output ./reports \
  --format sarif
```

### VulnRange Labs

Practice CVE exploitation with bundled challenges:

```bash
# List available labs
rtosploit vulnrange list

# Start a challenge (shows target info and hints)
rtosploit vulnrange start CVE-2018-16525

# Get progressive hints
rtosploit vulnrange hint CVE-2018-16525 --level 1   # general
rtosploit vulnrange hint CVE-2018-16525 --level 3   # near-spoiler

# Run the reference exploit
rtosploit vulnrange solve CVE-2018-16525

# Read the full writeup
rtosploit vulnrange writeup CVE-2018-16525
```

---

## Configuration

RTOSploit loads configuration in this order (later overrides earlier):

1. Built-in defaults
2. `~/.config/rtosploit/config.yaml` (user-wide)
3. `.rtosploit.yaml` (project-level, in current directory)
4. `--config PATH` (explicit override)
5. CLI flags (highest priority)

### Environment Variables

All config keys can be set via `RTOSPLOIT_` prefixed environment variables:

```bash
RTOSPLOIT_QEMU_BINARY=/opt/qemu/bin/qemu-system-arm
RTOSPLOIT_QEMU_TIMEOUT=30
RTOSPLOIT_LOGGING_LEVEL=debug
```

### Machine YAML Files

Machine definitions live in `configs/machines/`. The filename stem is the `--machine` argument:

- `mps2-an385` — Cortex-M3 (most FreeRTOS/ThreadX demos)
- `mps2-an505` — Cortex-M33 with TrustZone
- `stm32f4` — Cortex-M4

### Fuzzer Profiles

Fuzzer profiles live in `configs/fuzzer/`:

| Profile | Timeout | Corpus Max | Use Case |
|---------|---------|------------|----------|
| `fast.yaml` | 500ms | 5,000 | Quick CI checks |
| `default.yaml` | 1,000ms | 10,000 | Standard testing |
| `thorough.yaml` | 2,000ms | 50,000 | Deep analysis |

---

## Bundled Firmware

Pre-built firmware images in `vulnrange/downloaded_firmware/`:

| Firmware | RTOS | Architecture | Machine |
|----------|------|--------------|---------|
| `freertos-full-demo-mps2-an385.elf` | FreeRTOS | Cortex-M3 | `mps2-an385` |
| `freertos-mpu-demo-mps2-an385.elf` | FreeRTOS (MPU) | Cortex-M3 | `mps2-an385` |
| `freertos-mpu-mps2-an385.elf` | FreeRTOS (MPU) | Cortex-M3 | `mps2-an385` |
| `freertos-tcp-echo-mps2-an385.elf` | FreeRTOS+TCP | Cortex-M3 | `mps2-an385` |
| `threadx-sample-cortex-m3.elf` | ThreadX | Cortex-M3 | `mps2-an385` |
| `esp32-wroom32-at-v3.4.0.0-*.bin` | ESP-AT | ESP32 | — |
| `micropython-esp32-generic-v1.27.0.bin` | MicroPython | ESP32 | — |
| `zephyr-pico2-blinky.bin` | Zephyr | RP2350 | — |
| `zephyr-pico2-pid-control.bin` | Zephyr | RP2350 | — |

The MPS2 AN385 ELF files work out of the box with `--machine mps2-an385`.

---

## Troubleshooting

### QEMU Version Mismatch

```
Error: QEMU version 8.2.0 is below minimum required 9.0.0
```

Your system QEMU is too old. Either:
- Build QEMU from source (see [Installing QEMU](#building-qemu-from-source))
- Use Docker, which bundles a compatible version
- Set `RTOSPLOIT_QEMU_BINARY` to point to a newer build

### Port Conflicts (1234 / 4444)

```
Error: Address already in use: port 1234
```

Another process is using the GDB or serial port. Fix:

```bash
# Find what's using port 1234
lsof -i :1234

# Use a different port
rtosploit emulate --firmware fw.elf --machine mps2-an385 --gdb-port 3333

# Or in Docker, change the host port mapping:
# docker compose run --rm -p 3333:1234 rtosploit emulate ...
```

### Orphaned QEMU Processes

If RTOSploit exits abnormally, QEMU processes may remain running:

```bash
# Find orphaned QEMU processes
ps aux | grep qemu-system

# Kill them
pkill -f qemu-system-arm
```

### Docker Permission Issues

```
Error: permission denied while trying to connect to the Docker daemon
```

Add your user to the `docker` group:

```bash
sudo usermod -aG docker $USER
# Log out and back in for group change to take effect
```

### Docker Build Context Too Large

If `docker compose build` is slow, verify `.dockerignore` is present. Without it, the entire repository (including `.venv/`, `target/`, `.git/`) is sent as build context.

```bash
# Check context size (should be < 50 MB with .dockerignore)
docker compose build 2>&1 | head -5
```

### Firmware Not Found in Docker

Firmware must be placed in the mounted volume or referenced by its container path:

```bash
# Host firmware → mount via ./firmware/ directory
cp my-device.elf ./firmware/
docker compose run --rm rtosploit scan --firmware /firmware/my-device.elf --machine mps2-an385

# Bundled firmware → use container path
docker compose run --rm rtosploit scan \
  --firmware /rtosploit/vulnrange/downloaded_firmware/freertos-full-demo-mps2-an385.elf \
  --machine mps2-an385
```

### GDB Connection Refused in Docker

Use `--service-ports` with `docker compose run` to expose mapped ports:

```bash
# Without --service-ports, ports are NOT published
docker compose run --rm --service-ports rtosploit emulate \
  --firmware /firmware/fw.elf --machine mps2-an385 --gdb
```

### Rust Fuzzer Not Found

If `cargo build --release` was not run, RTOSploit falls back to simulation mode for fuzzing. This is expected — simulation mode produces synthetic crashes for testing the triage and reporting pipeline.

To enable real coverage-guided fuzzing:

```bash
# Local
cargo build --release

# Docker — the Dockerfile builds it automatically
docker compose build
```
