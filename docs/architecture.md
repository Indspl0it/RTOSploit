# Architecture

RTOSploit is organized as a Python package with optional Rust crates for
performance-critical components.

## Layer Overview

```
+----------------------------------------------------------+
|  CLI (Click + Rich)    |  Console (prompt_toolkit)       |
+----------------------------------------------------------+
|  Exploit Framework     |  VulnRange Lab                  |
|  (base, registry,      |  (manifest, manager)            |
|   runner, target)      |                                 |
+----------------------------------------------------------+
|  Analysis              |  Payload Generator              |
|  (fingerprint, heap,   |  (shellcode, ROP)               |
|   mpu, strings)        |                                 |
+----------------------------------------------------------+
|  Emulation Engine      |  Instrumentation Bus            |
|  (QEMU, QMP, GDB,      |  (events, telemetry,           |
|   memory, snapshot)    |   trace_writer)                 |
+----------------------------------------------------------+
|  Rust Crates                                             |
|  rtosploit-fuzzer  |  rtosploit-svd  |  rtosploit-payloads |
+----------------------------------------------------------+
```

## Key Components

- **Exploit Modules**: Python classes extending `ExploitModule`. Auto-discovered from `rtosploit/exploits/<rtos>/`.
- **ExploitRegistry**: Singleton registry with `discover()`, `get()`, `search()`.
- **QEMUInstance**: Manages QEMU process lifecycle via Popen.
- **QMPClient**: JSON-RPC over Unix socket for QEMU management.
- **GDBClient**: GDB Remote Serial Protocol over TCP.
- **InstrumentationBus**: Thread-safe event dispatcher for runtime telemetry.
- **CrashDetector**: 6-layer crash detection system.
- **VulnRangeManager**: Manages CVE reproduction lab.

## Rust/Python Boundary

The `rtosploit-payloads` Rust crate is designed to be linked into Python via
`maturin`/`PyO3`. Currently, the Python layer uses pure-Python equivalents.
