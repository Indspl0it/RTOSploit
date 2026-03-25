# Architecture

RTOSploit is organized as a layered Python package with an optional native Rust component for performance-critical fuzzing. The system is designed around three entry points — interactive mode, CLI subcommands, and a programmatic Python API — all sharing the same core analysis and emulation engine.

---

## System Overview

```mermaid
flowchart TB
    subgraph Entry["Entry Points"]
        interactive["Interactive Mode\n(questionary menus)"]
        cli["CLI Subcommands\n(Click)"]
        api["Python API\n(programmatic)"]
    end

    subgraph Core["Core Engine"]
        analysis["Static Analysis\nfingerprint · heap · MPU · strings"]
        emulation["Emulation Layer\nQEMU orchestration · GDB · QMP"]
        fuzzer["Fuzzing Engine\nAFL bitmap · crash dedup · corpus"]
        scanners["Vulnerability Scanners\nFreeRTOS · ThreadX · Zephyr"]
        cve["CVE Intelligence\ndatabase · correlator · NVD sync"]
    end

    subgraph Post["Post-Processing"]
        triage["Crash Triage\nclassify · minimize · rank"]
        coverage["Coverage Analysis\nbitmap reader · mapper · visualizer"]
        reporting["Reporting\nSARIF · HTML dashboard"]
    end

    subgraph Infra["Infrastructure"]
        config["Config System\nYAML · env vars · CLI flags"]
        machines["Machine Configs\nQEMU machine YAML definitions"]
        payloads["Payload Generation\nshellcode · ROP chains"]
    end

    interactive --> Core
    cli --> Core
    api --> Core

    Core --> Post
    Infra --> Core
    Infra --> Post
```

---

## Entry Point Routing

When `rtosploit` is invoked, `main()` in `cli/main.py` inspects `sys.argv` before Click parses anything:

```mermaid
flowchart LR
    invoke["rtosploit invoked"] --> check{"sys.argv\nhas subcommand?"}
    check -- "No args or\nonly global flags" --> interactive["InteractiveApp.run()"]
    check -- "Subcommand present\n(scan, fuzz, ...)" --> click["Click CLI\ndispatch"]
    check -- "--help or\n--version" --> help["Print and exit"]
    interactive --> app["InteractiveApp\nmenu loop"]
    click --> cmd["Click Command\nhandler"]
```

Global flags (`--verbose`, `--quiet`, `--json`, `--config`, `--debug`) are always evaluated regardless of routing path.

---

## Interactive Mode Architecture

The interactive mode is built around a single `InteractiveApp` instance that holds an `InteractiveSession` and dispatches menu selections to lazy-imported handlers.

```mermaid
flowchart TD
    start["interactive_main()"] --> banner["Print Banner"]
    banner --> loop{"Session has\nfirmware?"}

    loop -- "No" --> mainmenu["prompt_main_menu()\nquestionary.select"]
    loop -- "Yes" --> fwmenu["prompt_firmware_menu()\nquestionary.select"]

    mainmenu --> dispatch["InteractiveApp._dispatch(action)"]
    fwmenu --> dispatch

    dispatch --> exit_action["action == 'exit'\nreturn False → break"]
    dispatch --> load["load_firmware_interactive()\npath prompt → load → fingerprint → info panel"]
    dispatch --> h_scan["handlers/scanning.py\nCIPipeline"]
    dispatch --> h_cve["handlers/cve.py\nCVEDatabase / CVECorrelator"]
    dispatch --> h_console["handlers/exploits.py\nRTOSploitConsole.run()"]
    dispatch --> h_boot["handlers/emulation.py\nQEMUInstance.start()"]
    dispatch --> h_fuzz["handlers/fuzzing.py\nrun_dashboard()"]
    dispatch --> h_analysis["handlers/analysis.py\nfingerprint / heap / MPU / strings"]
    dispatch --> h_triage["handlers/triage.py\nTriagePipeline.run()"]
    dispatch --> h_report["handlers/reporting.py\ngenerate_sarif / generate_html"]
    dispatch --> h_cov["handlers/coverage.py\nCoverageMapper"]

    load --> session["session.firmware = FirmwareContext"]
    session --> loop
```

### Session State

```mermaid
classDiagram
    class InteractiveSession {
        +firmware: FirmwareContext | None
        +output_dir: Path
        +debug: bool
        +history: list[str]
        +has_firmware: bool
        +has_qemu: bool
    }

    class FirmwareContext {
        +path: Path
        +image: FirmwareImage
        +fingerprint: RTOSFingerprint | None
        +machine: str | None
        +machine_config: MachineConfig | None
        +qemu: QEMUInstance | None
        +size_kb: float
        +rtos_name: str
        +rtos_version: str
        +arch_name: str
    }

    InteractiveSession "1" --> "0..1" FirmwareContext : firmware
```

---

## CLI Layer

The CLI layer is a thin Click wrapper. Each subcommand file defines a single `@click.command`, validates inputs, and delegates to the core engine.

```mermaid
flowchart LR
    main["cli/main.py\n@click.group()"] --> emulate["commands/emulate.py"]
    main --> fuzz["commands/fuzz.py"]
    main --> exploit["commands/exploit.py"]
    main --> analyze["commands/analyze.py"]
    main --> cve_cmd["commands/cve.py"]
    main --> triage_cmd["commands/triage.py"]
    main --> coverage_cmd["commands/coverage.py"]
    main --> report_cmd["commands/report.py"]
    main --> scan_cmd["commands/scan.py"]
    main --> console_cmd["commands/console_cmd.py"]
    main --> payload_cmd["commands/payload.py"]
    main --> svd_cmd["commands/svd.py"]
    main --> vulnrange_cmd["commands/vulnrange.py"]
```

---

## Full Scan Pipeline

The `scan` command and `CIPipeline` orchestrate all phases in sequence:

```mermaid
sequenceDiagram
    actor User
    participant scan as rtosploit scan
    participant ci as CIPipeline
    participant analysis as Static Analysis
    participant cve as CVE Correlator
    participant qemu as QEMU
    participant fuzzer as Fuzzer
    participant triage as TriagePipeline
    participant report as Reporter

    User->>scan: rtosploit scan --firmware fw.bin --machine mps2-an385
    scan->>ci: CIPipeline(CIConfig).run()

    ci->>analysis: load_firmware(path)
    analysis-->>ci: FirmwareImage

    ci->>analysis: fingerprint_firmware(image)
    analysis-->>ci: RTOSFingerprint(rtos, version, confidence)

    ci->>analysis: detect_heap(image) + check_mpu(image) + extract_strings(image)
    analysis-->>ci: HeapInfo, MPUConfig, strings

    ci->>cve: CVECorrelator.correlate(fingerprint)
    cve-->>ci: CorrelationResult (matching CVEs)

    ci->>qemu: QEMUInstance.start(firmware, machine)
    qemu-->>ci: QEMU process running

    ci->>fuzzer: launch rtosploit-fuzzer (or simulation)
    fuzzer-->>ci: crash JSON files + coverage bitmap

    ci->>qemu: QEMUInstance.stop()

    ci->>triage: TriagePipeline.run(crash_dir)
    triage-->>ci: list[TriagedCrash]

    ci->>report: generate_sarif(findings, output)
    ci->>report: generate_html(findings, output)
    report-->>ci: report.sarif.json, report.html

    ci-->>scan: exit_code (0/1/2)
    scan-->>User: exit(code)
```

---

## Static Analysis Pipeline

Static analysis runs without QEMU and operates entirely on the firmware binary:

```mermaid
flowchart LR
    bin["firmware.bin\n(raw / ELF / HEX / SREC)"] --> loader["load_firmware()\nutils/binary.py"]
    loader --> image["FirmwareImage\n· data bytes\n· architecture\n· sections\n· symbols\n· entry point"]

    image --> fp["fingerprint_firmware()\nanalysis/fingerprint.py"]
    image --> heap["detect_heap()\nanalysis/heap_detect.py"]
    image --> mpu["check_mpu()\nanalysis/mpu_check.py"]
    image --> strings["extract_strings()\nanalysis/strings.py"]

    fp --> rtos["RTOSFingerprint\n· rtos_type\n· version\n· confidence\n· evidence"]
    heap --> heapinfo["HeapInfo\n· allocator_type\n· heap_base\n· heap_size"]
    mpu --> mpuconfig["MPUConfig\n· mpu_present\n· regions_configured\n· vulnerabilities"]
    strings --> strlist["list[tuple[int, str]]\n(address, value)"]
```

---

## Vulnerability Scanner Architecture

All scanner modules follow the `ScannerModule` abstract base class. The registry discovers them at runtime via Python's `importlib`.

```mermaid
classDiagram
    class ScannerModule {
        <<abstract>>
        +name: str
        +description: str
        +rtos: str
        +category: str
        +reliability: str
        +cve: str | None
        +options: dict[str, ScanOption]
        +register_options() void
        +check(target: ScanTarget) bool*
        +exploit(target: ScanTarget) ScanResult*
        +requirements() list[str]*
        +cleanup() void*
        +add_option(name, type, required, default, description) void
    }

    class ScanOption {
        +name: str
        +type: str
        +required: bool
        +default: Any
        +description: str
        +current_value: Any
    }

    class ScanResult {
        +module: str
        +status: str
        +target_rtos: str
        +technique: str
        +payload_delivered: bool
        +achieved: list[str]
        +registers_at_payload: dict
        +notes: list[str]
        +cve: str | None
    }

    class ScannerRegistry {
        +_modules: dict[str, type]
        +discover() void
        +get(path: str) type | None
        +search(term: str) list
    }

    ScannerModule "1" --> "*" ScanOption : options
    ScannerModule --> ScanResult : returns
    ScannerRegistry "1" --> "*" ScannerModule : manages
```

### Module Discovery Flow

```mermaid
flowchart LR
    registry["ScannerRegistry.discover()"] --> scan["Scan rtosploit/scanners/\nfreertos/ threadx/ zephyr/"]
    scan --> importlib["importlib.import_module()\nfor each .py file"]
    importlib --> inspect["Inspect for ScannerModule\nsubclasses"]
    inspect --> register["registry._modules[path] = cls"]
    register --> ready["Modules available\nfor use/search/run"]
```

---

## Fuzzing Architecture

```mermaid
flowchart TB
    subgraph Fuzzer["Fuzzing Layer"]
        harness["QEMU Harness\nqemu-system-arm -M mps2-an385"]
        bitmap["AFL Coverage Bitmap\n64KB shared memory"]
        mutation["Mutation Engine\nrtosploit-fuzzer (Rust)\nor simulation mode"]
        corpus["Corpus Manager\nseeds → interesting inputs"]
        crashes["Crash Collector\nJSON: registers, PC, fault addr"]
    end

    subgraph Dashboard["Live Dashboard (Rich)"]
        live["Rich Live()"]
        table["build_dashboard_table()\nelapsed · exec/s · crashes · coverage"]
    end

    mutation --> harness
    harness --> bitmap
    bitmap --> mutation
    harness --> crashes
    bitmap --> corpus
    corpus --> mutation

    harness --> live
    crashes --> table
    bitmap --> table
    table --> live
```

The shared `dashboard.py` module is imported by both `cli/commands/fuzz.py` (CLI mode) and `interactive/handlers/fuzzing.py` (interactive mode), ensuring identical rendering in both paths.

---

## Crash Triage Pipeline

```mermaid
flowchart TD
    crashes["crashes/*.json\n(QEMU fault records)"] --> load["Load crash files\nTriagePipeline.run()"]
    load --> replay["Replay each crash\nin QEMU"]
    replay --> classify["ExploitabilityClassifier\n· CFSR flags\n· fault type\n· PC control\n· SP control"]
    classify --> exploitable["EXPLOITABLE"]
    classify --> prob_exp["PROBABLY_EXPLOITABLE"]
    classify --> prob_not["PROBABLY_NOT_EXPLOITABLE"]
    classify --> unknown["UNKNOWN"]

    exploitable --> minimize["CrashMinimizer\nbinary-search input reduction"]
    prob_exp --> minimize

    minimize --> sort["Sort by exploitability\nEXPLOITABLE first"]
    sort --> results["list[TriagedCrash]\nwith minimized inputs"]
```

---

## CVE Intelligence Architecture

```mermaid
flowchart LR
    subgraph Local["Local Database"]
        bundled["bundled_cves.json\n(pre-populated)"]
        db["CVEDatabase\nload · save · search · lookup"]
    end

    subgraph Remote["Remote Sync"]
        nvd["NVDClient\nNIST NVD REST API"]
        apikey["API Key\n(optional, higher rate limit)"]
    end

    subgraph Correlation["Correlation"]
        correlator["CVECorrelator\ncorrelate(rtos, version)"]
        fp["RTOSFingerprint\nrtos_type · version"]
    end

    bundled --> db
    nvd --> db
    apikey --> nvd
    db --> correlator
    fp --> correlator
    correlator --> result["CorrelationResult\n· matching CVEs\n· exploitable subset\n· highest severity"]
```

---

## Reporting Pipeline

```mermaid
flowchart LR
    findings["list[Finding]\n(crashes · exploits · CVEs)"] --> models["reporting/models.py\nEngagementReport\n· findings\n· coverage stats\n· metadata"]

    models --> sarif["SARIFGenerator\nreport.sarif.json"]
    models --> html["HTMLGenerator\nreport.html"]

    sarif --> ide["IDE Integration\nVS Code · GitHub Code Scanning\nAzure DevOps"]
    html --> browser["HTML Dashboard\nseverity colors · finding details"]
```

### SARIF Structure

```mermaid
flowchart TD
    sarif["report.sarif.json"] --> runs["runs[]"]
    runs --> tool["tool\n· name: RTOSploit\n· rules[]"]
    runs --> results["results[]\none per finding"]
    results --> level["level: error/warning/note"]
    results --> message["message.text"]
    results --> locations["locations[]\n· physicalLocation\n· artifactLocation"]
    results --> props["properties\n· severity\n· exploitability\n· registers"]
```

---

## Payload Generation

```mermaid
flowchart LR
    subgraph Shellcode["Shellcode Generator"]
        arch["Architecture\narmv7m / riscv32"]
        stype["Type\nnop_sled · infinite_loop\nmpu_disable · vtor_redirect"]
        encoder["Encoder\nraw · xor · nullfree"]
        fmt["Format\nhex · c · python · raw"]
    end

    subgraph ROP["ROP Helper"]
        scan["Scan binary\nfor BX LR gadgets"]
        filter["Filter bad chars"]
        chain["Build chain\nmpu_disable · write_what_where\nvtor_overwrite"]
    end

    arch --> output["Output bytes"]
    stype --> output
    encoder --> output
    fmt --> output

    scan --> filter
    filter --> chain
    chain --> rop_out["ROP chain bytes"]
```

---

## Configuration System

RTOSploit uses a layered configuration system with clear precedence:

```mermaid
flowchart BT
    defaults["Built-in defaults"] --> user_cfg
    user_cfg["~/.config/rtosploit/config.yaml\n(user-wide)"] --> proj_cfg
    proj_cfg[".rtosploit.yaml\n(project-level)"] --> explicit_cfg
    explicit_cfg["--config PATH\n(explicit override)"] --> env
    env["RTOSPLOIT_* env vars"] --> cli_flags
    cli_flags["CLI flags\n(highest priority)"] --> final["RTOSploitConfig\nfinal resolved config"]
```

**Config sections:**

```yaml
qemu:
  binary: qemu-system-arm    # QEMU binary path
  timeout: 30                # Process timeout (seconds)

gdb:
  port: 1234                 # Default GDB port

output:
  format: text               # text | json
  color: true                # Enable Rich colors

logging:
  level: info                # debug | info | warning | error

fuzzer:
  default_timeout: 120       # Default fuzz duration
  jobs: 1                    # Default parallel instances
```

---

## Machine Configuration Schema

```mermaid
classDiagram
    class MachineConfig {
        +name: str
        +qemu_machine: str
        +cpu: str
        +architecture: str
        +memory: dict[str, MemoryRegion]
        +peripherals: dict[str, PeripheralConfig]
    }

    class MemoryRegion {
        +base: int
        +size: int
    }

    class PeripheralConfig {
        +name: str
        +base: int
        +size: int
        +irq: int | None
        +builtin: bool
    }

    MachineConfig "1" --> "*" MemoryRegion : memory regions
    MachineConfig "1" --> "*" PeripheralConfig : peripherals
```

Machines are discovered from `configs/machines/*.yaml`. The file stem is the machine identifier. Memory region overlap is validated at load time.

---

## Console REPL Architecture

The Metasploit-style console is built on `prompt_toolkit` with a custom completer and Rich output:

```mermaid
flowchart TD
    start["RTOSploitConsole.run()"] --> banner["Display ASCII banner"]
    banner --> ptk{"prompt_toolkit\navailable?"}

    ptk -- "Yes" --> session["PromptSession\n· FileHistory\n· AutoSuggestFromHistory\n· RTOSploitCompleter"]
    ptk -- "No" --> basic["Fallback: input()"]

    session --> loop["REPL loop\nprompt → input → dispatch"]
    basic --> loop

    loop --> dispatch["dispatch(line)"]
    dispatch --> use["cmd_use()\nload module from registry"]
    dispatch --> show["cmd_show()\noptions | info | modules"]
    dispatch --> set_cmd["cmd_set()\ntype-validated option set"]
    dispatch --> check_cmd["cmd_check()\nnon-destructive probe"]
    dispatch --> exploit_cmd["cmd_exploit()\nrun_exploit()"]
    dispatch --> search_cmd["cmd_search()\nfull-text across modules"]
    dispatch --> exit_cmd["exit / quit\nbreak loop"]

    use --> state["ConsoleState\n· current_module\n· option_values\n· active_qemu"]
```

---

## Module Dependency Map

```mermaid
flowchart TD
    cli["cli/"] --> interactive["interactive/"]
    cli --> exploits["exploits/"]
    cli --> analysis["analysis/"]
    cli --> cve_mod["cve/"]
    cli --> triage_mod["triage/"]
    cli --> coverage_mod["coverage/"]
    cli --> reporting["reporting/"]
    cli --> ci["ci/"]
    cli --> console["console/"]
    cli --> payloads["payloads/"]

    ci --> analysis
    ci --> cve_mod
    ci --> emulation["emulation/"]
    ci --> triage_mod
    ci --> reporting

    interactive --> analysis
    interactive --> cve_mod
    interactive --> triage_mod
    interactive --> reporting
    interactive --> emulation
    interactive --> exploits

    exploits --> emulation
    console --> exploits
    emulation --> config["config.py"]
    analysis --> utils["utils/binary.py"]
    triage_mod --> emulation
```

---

## Data Flow: Interactive Firmware Session

```mermaid
sequenceDiagram
    actor User
    participant app as InteractiveApp
    participant loader as firmware_loader
    participant analysis as analysis/
    participant session as InteractiveSession
    participant menu as Firmware Menu
    participant handler as handlers/

    User->>app: rtosploit (no args)
    app->>app: print_banner()
    app->>app: prompt_main_menu()
    User->>app: Select "Load Firmware"

    app->>loader: load_firmware_interactive(session)
    loader->>User: questionary.path("Firmware file path:")
    User->>loader: /path/to/firmware.bin

    loader->>analysis: load_firmware(path)
    analysis-->>loader: FirmwareImage

    loader->>analysis: fingerprint_firmware(image)
    analysis-->>loader: RTOSFingerprint(freertos, 10.4.3, 0.92)

    loader->>loader: _auto_detect_machine("armv7m") → "mps2-an385"
    loader->>loader: _display_firmware_info() → Rich panel

    loader->>User: "Override machine config? (y/N)"
    User->>loader: N

    loader->>session: session.firmware = FirmwareContext(...)

    app->>menu: prompt_firmware_menu()
    User->>menu: Select "Fuzz Firmware"

    menu->>handler: handle_fuzz(session, console)
    handler->>User: questionary prompts (timeout, corpus, output)
    User->>handler: 60s, ./out
    handler->>handler: run_dashboard(output, simulation, 60)
```

---

## Key Design Decisions

### Lazy Imports in Handlers
All interactive handlers use local imports inside functions. This means `questionary`, `rtosploit.emulation`, and other heavy modules are not imported at CLI startup — keeping `rtosploit --help` fast.

### Shared Dashboard Module
`interactive/dashboard.py` is imported by both `cli/commands/fuzz.py` and `interactive/handlers/fuzzing.py`. The dashboard rendering is identical whether you run `rtosploit fuzz` (CLI) or pick "Fuzz Firmware" from the interactive menu.

### Click `standalone_mode=False`
The CLI calls `cli(standalone_mode=False)` so exceptions propagate to `main()` for unified error handling with Rich panels and optional tracebacks.

### atexit Cleanup
`InteractiveApp.run()` registers `_cleanup()` with `atexit` so QEMU processes are always terminated — even on unexpected exits or exceptions.

### No Hardware Dependency
All emulation runs in QEMU. The code never opens raw serial ports or device files. Machine configurations are YAML-defined and the emulation layer validates QEMU binary presence and version at startup.
