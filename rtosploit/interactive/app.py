"""Main interactive application loop."""

from __future__ import annotations

import atexit
import logging
import sys

from rich.console import Console

from .banner import print_banner
from .menus import prompt_main_menu, prompt_firmware_menu
from .session import InteractiveSession

logger = logging.getLogger(__name__)


class InteractiveApp:
    """Main interactive mode application."""

    def __init__(self, debug: bool = False) -> None:
        self.console = Console()
        self.session = InteractiveSession(debug=debug)
        if debug:
            logging.basicConfig(
                level=logging.DEBUG,
                format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            )

    def run(self) -> None:
        """Main application loop."""
        atexit.register(self._cleanup)
        print_banner(self.console)
        self.console.print()

        try:
            while True:
                try:
                    if self.session.has_firmware:
                        action = prompt_firmware_menu(
                            console=self.console,
                            firmware=self.session.firmware,
                        )
                    else:
                        action = prompt_main_menu(console=self.console)

                    if action is None:
                        # User pressed Ctrl+C during menu
                        break

                    if not self._dispatch(action):
                        break

                except KeyboardInterrupt:
                    self.console.print("\n[yellow]Use Exit to quit.[/yellow]")
                    continue

        except KeyboardInterrupt:
            pass
        finally:
            self._cleanup()

        self.console.print("\n[dim]Goodbye![/dim]")

    def _dispatch(self, action: str) -> bool:
        """Dispatch a menu action. Returns False to exit."""
        self.session.history.append(action)

        if action == "exit":
            return False

        if action == "back":
            return True

        # Firmware loading
        if action == "load_firmware":
            self._handle_load_firmware()
            return True

        # Actions that don't require firmware
        if action == "quick_scan":
            self._handle_quick_scan()
            return True
        if action == "cve_search":
            self._handle_cve_search()
            return True
        if action == "console":
            self._handle_console()
            return True
        if action == "settings":
            self._handle_settings()
            return True
        if action == "vulnrange":
            self._handle_vulnrange()
            return True
        if action == "svd":
            self._handle_svd()
            return True
        if action == "payload":
            self._handle_payload()
            return True

        # Actions requiring firmware
        if not self.session.has_firmware:
            self.console.print("[red]Load firmware first.[/red]")
            return True

        handlers = {
            "boot_qemu": self._handle_boot_qemu,
            "attach_gdb": self._handle_attach_gdb,
            "fuzz": self._handle_fuzz,
            "exploits": self._handle_scanners,
            "full_scan": self._handle_full_scan,
            "analysis": self._handle_analysis,
            "cve_correlate": self._handle_cve_correlate,
            "triage": self._handle_triage,
            "coverage": self._handle_coverage,
            "reports": self._handle_reports,
            "rehost": self._handle_rehost,
        }

        handler = handlers.get(action)
        if handler:
            handler()
        else:
            self.console.print(f"[yellow]Unknown action: {action}[/yellow]")

        return True

    def _cleanup(self) -> None:
        """Clean up resources on exit."""
        if self.session.has_qemu:
            self.console.print("[dim]Stopping QEMU...[/dim]")
            try:
                self.session.firmware.qemu.stop()
            except Exception:
                pass

    # --- Placeholder handlers (implemented in later phases) ---

    def _handle_load_firmware(self) -> None:
        from .firmware_loader import load_firmware_interactive
        load_firmware_interactive(self.session, self.console)

    def _handle_quick_scan(self) -> None:
        from .handlers.scanning import handle_quick_scan
        handle_quick_scan(self.session, self.console)

    def _handle_cve_search(self) -> None:
        from .handlers.cve import handle_cve_search
        handle_cve_search(self.session, self.console)

    def _handle_console(self) -> None:
        from .handlers.scanners import handle_console
        handle_console(self.session, self.console)

    def _handle_settings(self) -> None:
        self.console.print("[dim]Settings not yet implemented.[/dim]")

    def _handle_boot_qemu(self) -> None:
        from .handlers.emulation import handle_boot_qemu
        handle_boot_qemu(self.session, self.console)

    def _handle_attach_gdb(self) -> None:
        from .handlers.emulation import handle_attach_gdb
        handle_attach_gdb(self.session, self.console)

    def _handle_fuzz(self) -> None:
        from .handlers.fuzzing import handle_fuzz
        handle_fuzz(self.session, self.console)

    def _handle_scanners(self) -> None:
        from .handlers.scanners import handle_scanners
        handle_scanners(self.session, self.console)

    def _handle_full_scan(self) -> None:
        from .handlers.scanning import handle_full_scan
        handle_full_scan(self.session, self.console)

    def _handle_analysis(self) -> None:
        from .handlers.analysis import handle_analysis
        handle_analysis(self.session, self.console)

    def _handle_cve_correlate(self) -> None:
        from .handlers.cve import handle_cve_correlate
        handle_cve_correlate(self.session, self.console)

    def _handle_triage(self) -> None:
        from .handlers.triage import handle_triage
        handle_triage(self.session, self.console)

    def _handle_coverage(self) -> None:
        from .handlers.coverage import handle_coverage
        handle_coverage(self.session, self.console)

    def _handle_reports(self) -> None:
        from .handlers.reporting import handle_reports
        handle_reports(self.session, self.console)

    def _handle_vulnrange(self) -> None:
        from .handlers.vulnrange import handle_vulnrange
        handle_vulnrange(self.session, self.console)

    def _handle_svd(self) -> None:
        from .handlers.svd_ops import handle_svd
        handle_svd(self.session, self.console)

    def _handle_payload(self) -> None:
        from .handlers.payload import handle_payload
        handle_payload(self.session, self.console)

    def _handle_rehost(self) -> None:
        from .handlers.rehost import handle_rehost
        handle_rehost(self.session, self.console)


def interactive_main(debug: bool = False) -> None:
    """Entry point for interactive mode."""
    try:
        import questionary  # noqa: F401
    except ImportError:
        console = Console()
        console.print(
            "[red]Interactive mode requires 'questionary'. "
            "Install with: pip install questionary>=2.1[/red]"
        )
        sys.exit(1)

    app = InteractiveApp(debug=debug)
    app.run()
