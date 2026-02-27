# Installation

## System Requirements

- Python 3.12+
- Rust 1.75+ (for fuzzer and payload crates)
- QEMU 9.0+ with ARM system emulation support
- GDB multiarch (optional, for debugging)
- arm-none-eabi-gcc 12+ (optional, for building firmware)

## Quick Install

### From PyPI (recommended)

```bash
pip install rtosploit
```

### From Source

```bash
git clone https://github.com/rtosploit/rtosploit
cd rtosploit
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Install QEMU

**Linux (Ubuntu/Debian):**
```bash
sudo apt install qemu-system-arm
qemu-system-arm --version  # Should be >= 9.0
```

**macOS (Homebrew):**
```bash
brew install qemu
```

**Docker (no local install needed):**
```bash
docker pull rtosploit/rtosploit:latest
docker run -it rtosploit/rtosploit rtosploit --version
```

### Install Rust Crates (for fuzzer)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
cargo build --release
```

## Verify Installation

```bash
rtosploit --version
rtosploit exploit list
```
