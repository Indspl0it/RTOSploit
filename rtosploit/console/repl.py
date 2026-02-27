"""RTOSploit interactive console REPL."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .state import ConsoleState

logger = logging.getLogger(__name__)


def _validate_option_value(opt_type: str, value: str) -> tuple[bool, str]:
    """Validate a value against an option type.

    Returns (is_valid, error_message).
    """
    t = opt_type.lower() if opt_type else "str"

    if t in ("int", "integer"):
        try:
            int(value)
        except ValueError:
            return False, f"Expected integer, got: {value}"

    elif t in ("bool", "boolean"):
        if value.lower() not in ("true", "false", "yes", "no", "1", "0"):
            return False, f"Expected boolean (true/false/yes/no/1/0), got: {value}"

    elif t == "float":
        try:
            float(value)
        except ValueError:
            return False, f"Expected float, got: {value}"

    elif t == "port":
        try:
            port = int(value)
        except ValueError:
            return False, f"Expected port number (1-65535), got: {value}"
        else:
            if port < 1 or port > 65535:
                return False, f"Port must be 1-65535, got: {port}"

    # "str", "string", "path", and anything else: accept any string
    return True, ""

BANNER = r"""
  ____  _____ ___  ____        _       _ _
 |  _ \|_   _/ _ \/ ___| _ __ | | ___ (_) |_
 | |_) | | || | | \___ \| '_ \| |/ _ \| | __|
 |  _ <  | || |_| |___) | |_) | | (_) | | |_
 |_| \_\ |_| \___/|____/| .__/|_|\___/|_|\__|
                         |_|
"""

VERSION = "0.1.0"

STATUS_INFO    = "[bold blue][*][/bold blue]"
STATUS_SUCCESS = "[bold green][+][/bold green]"
STATUS_FAILURE = "[bold red][-][/bold red]"
STATUS_WARNING = "[bold yellow][!][/bold yellow]"


def _inst_attr(inst: object, *names: str, default: str = "") -> str:
    """Return first matching attribute value from an exploit module instance."""
    for name in names:
        val = getattr(inst, name, None)
        if val is not None:
            return str(val)
    return default


class RTOSploitConsole:
    """Metasploit-style interactive console for RTOSploit."""

    def __init__(self):
        self.console = Console()
        self.state = ConsoleState()
        self._registry = None
        self._history_file = Path.home() / ".config" / "rtosploit" / "history"
        self._history_file.parent.mkdir(parents=True, exist_ok=True)

    def _get_registry(self):
        if self._registry is None:
            from rtosploit.exploits.registry import ExploitRegistry
            self._registry = ExploitRegistry()
            self._registry.discover()
        return self._registry

    def _print(self, prefix: str, message: str) -> None:
        self.console.print(f"{prefix} {message}")

    def info(self, msg: str) -> None:
        self._print(STATUS_INFO, msg)

    def success(self, msg: str) -> None:
        self._print(STATUS_SUCCESS, msg)

    def failure(self, msg: str) -> None:
        self._print(STATUS_FAILURE, msg)

    def warning(self, msg: str) -> None:
        self._print(STATUS_WARNING, msg)

    def cmd_use(self, args: str) -> None:
        """use MODULE — load an exploit module."""
        if not args:
            self.failure("Usage: use <module_path>  (e.g. use freertos/heap_overflow)")
            return

        registry = self._get_registry()
        cls = registry.get(args)
        if cls is None:
            self.failure(f"Module not found: [cyan]{args}[/cyan]")
            self.info("Run [dim]search[/dim] to list available modules.")
            return

        instance = cls()
        self.state.set_module(args, instance)
        self.success(f"Loaded module: [cyan]{args}[/cyan]")
        self.info("Type [dim]show options[/dim] to see available settings.")

    def cmd_show(self, args: str) -> None:
        """show options|info|modules — display information."""
        sub = args.strip().lower()

        if sub == "options":
            if not self.state.current_module_instance:
                self.failure("No module selected. Use [dim]use <module>[/dim] first.")
                return

            inst = self.state.current_module_instance
            table = Table(
                title=f"Options: {self.state.current_module}",
                show_header=True,
                header_style="bold cyan",
            )
            table.add_column("Name", style="cyan")
            table.add_column("Current", style="green")
            table.add_column("Default", style="dim")
            table.add_column("Req?", style="red")
            table.add_column("Description", style="white")

            for name, opt in inst.options.items():
                current = self.state.option_values.get(name, "")
                default = str(opt.default) if opt.default is not None else ""
                req = "YES" if opt.required else "no"
                table.add_row(name, current or "-", default or "-", req, opt.description)

            self.console.print(table)

        elif sub == "info":
            if not self.state.current_module_instance:
                self.failure("No module selected.")
                return

            inst = self.state.current_module_instance
            name = _inst_attr(inst, "name")
            description = _inst_attr(inst, "description")
            self.console.print(Panel(
                f"[bold]{name}[/bold]\n\n{description}",
                title=f"[cyan]{self.state.current_module}[/cyan]",
                border_style="cyan",
            ))
            cve = _inst_attr(inst, "cve", "cves")
            if cve:
                self.info(f"CVE: [yellow]{cve}[/yellow]")
            self.info(f"Reliability: [yellow]{_inst_attr(inst, 'reliability')}[/yellow]")
            self.info(f"Category: [yellow]{_inst_attr(inst, 'category')}[/yellow]")

        elif sub in ("modules", "exploits", ""):
            registry = self._get_registry()
            table = Table(
                title="Available Exploit Modules",
                show_header=True,
                header_style="bold cyan",
            )
            table.add_column("Module Path", style="cyan")
            table.add_column("RTOS", style="green")
            table.add_column("Category", style="yellow")
            table.add_column("Reliability", style="magenta")

            for path, cls in sorted(registry._modules.items()):
                inst = cls()
                table.add_row(
                    path,
                    _inst_attr(inst, "target_rtos", "rtos"),
                    _inst_attr(inst, "category"),
                    _inst_attr(inst, "reliability"),
                )

            self.console.print(table)

        else:
            self.failure(f"Unknown show target: [dim]{sub}[/dim]")
            self.info("Available: [dim]show options[/dim], [dim]show info[/dim], [dim]show modules[/dim]")

    def cmd_set(self, args: str) -> None:
        """set KEY VALUE — set a module option."""
        if not self.state.current_module_instance:
            self.failure("No module selected.")
            return

        parts = args.split(None, 1)
        if len(parts) != 2:
            self.failure("Usage: set <option_name> <value>")
            return

        key, value = parts
        inst = self.state.current_module_instance
        if key not in inst.options:
            self.warning(f"Unknown option: [dim]{key}[/dim]")
            self.state.option_values[key] = value
            self.success(f"{key} => [cyan]{value}[/cyan]")
            return

        opt = inst.options[key]

        # Type validation
        valid, err = _validate_option_value(opt.type, value)
        if not valid:
            self.failure(f"Invalid value for [cyan]{key}[/cyan]: {err}")
            return

        # Choices validation (if the option defines choices)
        choices = getattr(opt, "choices", None)
        if choices and value not in choices:
            self.failure(
                f"Invalid value for [cyan]{key}[/cyan]: "
                f"must be one of {', '.join(choices)}"
            )
            return

        self.state.option_values[key] = value
        self.success(f"{key} => [cyan]{value}[/cyan]")

    def cmd_unset(self, args: str) -> None:
        """unset KEY — clear a module option."""
        key = args.strip()
        if key in self.state.option_values:
            del self.state.option_values[key]
            self.info(f"Unset: [dim]{key}[/dim]")
        else:
            self.warning(f"Option not set: [dim]{key}[/dim]")

    def cmd_check(self, args: str) -> None:
        """check — run non-destructive vulnerability check."""
        if not self.state.current_module_instance:
            self.failure("No module selected.")
            return

        firmware = self.state.option_values.get("firmware", "")
        if not firmware:
            self.failure("Set [dim]firmware[/dim] option first: set firmware /path/to/fw.bin")
            return

        self.info(f"Running check for [cyan]{self.state.current_module}[/cyan]...")

        try:
            from rtosploit.emulation.machines import MachineConfig
            machine = self.state.option_values.get("machine", "mps2-an385")
            machine_config = MachineConfig(
                name=machine,
                qemu_machine=machine,
                cpu="cortex-m3",
                memory_mb=16,
                architecture="arm",
            )
            from rtosploit.exploits.target import ExploitTarget
            target = ExploitTarget(firmware_path=firmware, machine_config=machine_config)
            inst = self.state.current_module_instance
            result = inst.check(target)
            if result:
                self.success("Target appears vulnerable.")
            else:
                self.warning("Target does not appear vulnerable (or check inconclusive).")
        except Exception as e:
            self.failure(f"Check error: {e}")

    def cmd_exploit(self, args: str) -> None:
        """exploit / run — execute current module."""
        if not self.state.current_module_instance:
            self.failure("No module selected. Use [dim]use <module>[/dim] first.")
            return

        firmware = self.state.option_values.get("firmware", "")
        if not firmware:
            self.failure("Set required options first: [dim]set firmware /path/to/fw.bin[/dim]")
            return

        self.info(f"Executing: [cyan]{self.state.current_module}[/cyan]")

        try:
            from rtosploit.exploits.runner import run_exploit
            result = run_exploit(self.state.current_module, dict(self.state.option_values))
            self.state.last_result = result

            if result.status == "success":
                self.success("Exploit succeeded!")
            else:
                self.failure(f"Exploit status: {result.status}")

            if result.notes:
                for note in result.notes:
                    self.info(note)
        except Exception as e:
            self.failure(f"Exploit error: {e}")
            logger.debug("Exploit error", exc_info=True)

    def cmd_back(self, args: str) -> None:
        """back — deselect current module."""
        if self.state.current_module:
            self.info(f"Deselected: [dim]{self.state.current_module}[/dim]")
            self.state.clear_module()
        else:
            self.info("No module selected.")

    def cmd_search(self, args: str) -> None:
        """search TERM — search modules by name/CVE/RTOS/category."""
        registry = self._get_registry()
        term = args.strip().lower()

        matches = []
        for path, cls in registry._modules.items():
            inst = cls()
            cve = _inst_attr(inst, "cve", "cves")
            rtos = _inst_attr(inst, "target_rtos", "rtos")
            description = _inst_attr(inst, "description")
            if (
                term in path.lower()
                or term in _inst_attr(inst, "name").lower()
                or term in rtos.lower()
                or term in _inst_attr(inst, "category").lower()
                or term in cve.lower()
                or term in description.lower()
            ):
                matches.append((path, inst))

        if not matches:
            self.warning(f"No modules found matching: [dim]{term}[/dim]")
            return

        table = Table(
            title=f"Search results for '{term}'",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Module Path", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("RTOS", style="green")
        table.add_column("CVE", style="yellow")
        table.add_column("Reliability", style="magenta")

        for path, inst in sorted(matches):
            cve = _inst_attr(inst, "cve", "cves") or "-"
            table.add_row(
                path,
                _inst_attr(inst, "name"),
                _inst_attr(inst, "target_rtos", "rtos"),
                cve,
                _inst_attr(inst, "reliability"),
            )

        self.console.print(table)
        self.info(f"{len(matches)} module(s) found.")

    def cmd_help(self, args: str) -> None:
        """help — display available commands."""
        help_text = Table(title="Available Commands", show_header=True, header_style="bold cyan")
        help_text.add_column("Command", style="cyan", no_wrap=True)
        help_text.add_column("Description", style="white")

        commands = [
            ("use <module>",       "Load an exploit module (e.g. use freertos/heap_overflow)"),
            ("show options",       "Display current module options and values"),
            ("show info",          "Display current module information and description"),
            ("show modules",       "List all available exploit modules"),
            ("set <key> <value>",  "Set a module option value"),
            ("unset <key>",        "Clear a module option"),
            ("check",              "Run non-destructive vulnerability check"),
            ("exploit / run",      "Execute current module's exploit"),
            ("back",               "Deselect current module"),
            ("search <term>",      "Search modules by name, CVE, RTOS, or category"),
            ("banner",             "Display the RTOSploit banner"),
            ("version",            "Show version information"),
            ("help",               "Show this help message"),
            ("exit / quit",        "Exit the console"),
        ]

        for cmd, desc in commands:
            help_text.add_row(cmd, desc)

        self.console.print(help_text)

    def cmd_banner(self, args: str) -> None:
        """banner — display ASCII art banner."""
        self.console.print(f"[bold cyan]{BANNER}[/bold cyan]")
        self.console.print(
            f"  [bold]RTOSploit[/bold] v{VERSION} — RTOS Exploitation & Bare-Metal Fuzzing Framework"
        )
        self.console.print(
            "  [dim]Supports: FreeRTOS, ThreadX, Zephyr | Targets: ARM Cortex-M, RISC-V[/dim]\n"
        )

    def cmd_version(self, args: str) -> None:
        """version — show version information."""
        self.info(f"RTOSploit v[cyan]{VERSION}[/cyan]")

    def dispatch(self, line: str) -> bool:
        """Dispatch a command line. Returns False to exit."""
        line = line.strip()
        if not line or line.startswith("#"):
            return True

        self.state.command_history.append(line)

        parts = line.split(None, 1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        if cmd in ("exit", "quit"):
            return False
        elif cmd == "use":
            self.cmd_use(args)
        elif cmd == "show":
            self.cmd_show(args)
        elif cmd == "set":
            self.cmd_set(args)
        elif cmd == "unset":
            self.cmd_unset(args)
        elif cmd == "check":
            self.cmd_check(args)
        elif cmd in ("exploit", "run"):
            self.cmd_exploit(args)
        elif cmd == "back":
            self.cmd_back(args)
        elif cmd == "search":
            self.cmd_search(args)
        elif cmd == "help":
            self.cmd_help(args)
        elif cmd == "banner":
            self.cmd_banner(args)
        elif cmd == "version":
            self.cmd_version(args)
        else:
            self.failure(f"Unknown command: [dim]{cmd}[/dim]  (type [dim]help[/dim] for list)")

        return True

    def run(self) -> None:
        """Start the interactive console."""
        self.cmd_banner("")

        try:
            from prompt_toolkit import PromptSession
            from prompt_toolkit.history import FileHistory
            from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
            from prompt_toolkit.completion import Completer, Completion

            all_commands = [
                "use", "show", "set", "unset", "check", "exploit", "run",
                "back", "search", "help", "banner", "version", "exit", "quit",
            ]

            registry = self._get_registry()
            module_paths = list(registry._modules.keys())

            console_ref = self

            class RTOSploitCompleter(Completer):
                """Context-aware completer for the RTOSploit console."""

                def get_completions(self, document, complete_event):
                    text = document.text_before_cursor
                    text_lower = text.lower()

                    # "use <partial>" -> complete module paths
                    if text_lower.startswith("use "):
                        partial = text[4:]
                        for path in module_paths:
                            if path.startswith(partial) or path.lower().startswith(partial.lower()):
                                yield Completion(path, start_position=-len(partial))

                    # "set <partial_option>" -> complete option names
                    elif text_lower.startswith("set "):
                        after_set = text[4:]
                        # Only complete option name (no space yet = still typing option name)
                        if " " not in after_set:
                            inst = console_ref.state.current_module_instance
                            if inst is not None and hasattr(inst, "options"):
                                for name in inst.options:
                                    if name.lower().startswith(after_set.lower()):
                                        yield Completion(name, start_position=-len(after_set))

                    # "show <partial>" -> complete show sub-commands
                    elif text_lower.startswith("show "):
                        partial = text[5:]
                        for sub in ("options", "info", "modules", "exploits"):
                            if sub.startswith(partial.lower()):
                                yield Completion(sub, start_position=-len(partial))

                    # "unset <partial>" -> complete from set option names
                    elif text_lower.startswith("unset "):
                        partial = text[6:]
                        for name in console_ref.state.option_values:
                            if name.lower().startswith(partial.lower()):
                                yield Completion(name, start_position=-len(partial))

                    # Default: complete command names
                    else:
                        for cmd in all_commands:
                            if cmd.startswith(text_lower):
                                yield Completion(cmd, start_position=-len(text))

            completer = RTOSploitCompleter()

            session = PromptSession(
                history=FileHistory(str(self._history_file)),
                auto_suggest=AutoSuggestFromHistory(),
                completer=completer,
            )

            while True:
                try:
                    prompt = self.state.get_prompt()
                    line = session.prompt(prompt)
                    if not self.dispatch(line):
                        break
                except KeyboardInterrupt:
                    self.console.print()
                    self.warning("Use [dim]exit[/dim] or [dim]quit[/dim] to exit.")
                except EOFError:
                    break

        except ImportError:
            self._run_basic()

        self.console.print(f"\n{STATUS_INFO} Goodbye!")
        self.state.cleanup()

    def _run_basic(self) -> None:
        """Fallback REPL using basic input()."""
        while True:
            try:
                prompt = self.state.get_prompt()
                line = input(prompt)
                if not self.dispatch(line):
                    break
            except KeyboardInterrupt:
                print()
                print("[!] Use exit or quit to exit.")
            except EOFError:
                break
