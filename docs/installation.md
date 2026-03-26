# Installation

This guide covers installing RTOSploit, setting up QEMU, and optionally building the native Rust fuzzer.

---

## System Requirements

| Requirement | Minimum |
|-------------|---------|
| Python | 3.10 or later |
| QEMU | 9.0 or later |
| OS | Linux, macOS, Windows (WSL2 recommended) |
| RAM | 2 GB |
| Disk | 500 MB (plus firmware files) |

---

## Python Setup

### Create a Virtual Environment

```bash
git clone https://github.com/Indspl0it/RTOSploit
cd rtosploit
python3 -m venv .venv
source .venv/bin/activate       # Linux/macOS
# .venv\Scripts\activate        # Windows (PowerShell)
```

### Install the Package

```bash
# Runtime only
pip install -e .

# With development tools (pytest, mypy, ruff, black)
pip install -e ".[dev]"
```

### Verify

```bash
rtosploit --help
```

---

## QEMU

RTOSploit requires QEMU 9.0 or later. Earlier versions will be rejected at runtime.

### Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install qemu-system-arm qemu-system-misc
qemu-system-arm --version
```

If the package manager provides an older QEMU, build from source:

```bash
# Install build dependencies
sudo apt install build-essential ninja-build pkg-config libglib2.0-dev libpixman-1-dev

# Download and build
wget https://download.qemu.org/qemu-9.2.0.tar.xz
tar xf qemu-9.2.0.tar.xz
cd qemu-9.2.0
./configure --target-list=arm-softmmu,riscv32-softmmu --disable-docs
make -j$(nproc)
sudo make install
```

### macOS

```bash
brew install qemu
qemu-system-arm --version
```

### Windows (WSL2)

Use the Debian/Ubuntu instructions inside a WSL2 environment. RTOSploit's terminal output is fully functional in WSL2 terminals (Windows Terminal, VS Code integrated terminal).

### Verify the Version

```bash
qemu-system-arm --version
# QEMU emulator version 9.x.x (...)
```

If you see a version below 9.0, RTOSploit will print an error and refuse to start QEMU.

---

## Optional: Unicorn Engine

For high-speed fuzzing of real hardware firmware (no QEMU machine required):

```bash
pip install unicorn
```

This enables the `--engine unicorn` option on `fuzz` and `rehost` commands, providing ~700 exec/sec with Peripheral Input Playback (PIP).

---

## Optional: NVD API Key

CVE update operations work without an API key, but NIST rate-limits unauthenticated requests. For CI environments or frequent updates, obtain a free API key from https://nvd.nist.gov/developers/request-an-api-key and set it:

```bash
export NVD_API_KEY=your-api-key-here
# or add to your shell profile
```

---

## Configuration

RTOSploit looks for a config file in (precedence order):
1. `~/.config/rtosploit/config.yaml` — user-wide defaults
2. `.rtosploit.yaml` — project-level (current directory)
3. `--config PATH` flag — explicit override

A minimal config to point at a custom QEMU binary:

```yaml
qemu:
  binary: /usr/local/bin/qemu-system-arm
  timeout: 30

logging:
  level: info
```

---

## Uninstall

```bash
pip uninstall rtosploit
# Remove user config and history
rm -rf ~/.config/rtosploit
```
