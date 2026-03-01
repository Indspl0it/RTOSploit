"""Visualize coverage data as terminal output (Rich) or HTML (Jinja2)."""

from __future__ import annotations

import os
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from rtosploit.coverage.bitmap_reader import CoverageMap


TEMPLATES_DIR = Path(__file__).parent / "templates"


class CoverageVisualizer:
    """Render coverage heatmaps for terminal or HTML output.

    Args:
        coverage_map: The coverage data to visualize.
        disassembly: List of ``(address, mnemonic, op_str)`` from Capstone.
    """

    def __init__(
        self,
        coverage_map: CoverageMap,
        disassembly: list[tuple[int, str, str]],
    ) -> None:
        self.coverage_map = coverage_map
        self.disassembly = disassembly

    def render_terminal(self, max_lines: int = 50) -> str:
        """Render a terminal-friendly coverage view with Rich markup.

        Green lines are covered, red lines are uncovered. Brighter green
        indicates higher hit counts (hotter code).

        Args:
            max_lines: Maximum number of disassembly lines to include.

        Returns:
            String with Rich markup suitable for ``Console.print()``.
        """
        lines: list[str] = []
        stats = self.get_stats()

        # Header
        lines.append("[bold cyan]Coverage Summary[/bold cyan]")
        lines.append(
            f"  Instructions: {stats['covered_instructions']}/{stats['total_instructions']} "
            f"({stats['coverage_percent']:.1f}%)"
        )
        lines.append(f"  Edges: {stats['total_edges']}")
        lines.append("")
        lines.append(
            "[bold]  Address    | Instruction          | Hits[/bold]"
        )
        lines.append("  " + "-" * 50)

        # Find max hit count for brightness scaling
        max_hits = max(self.coverage_map.hot_addresses.values()) if self.coverage_map.hot_addresses else 1

        for addr, mnemonic, op_str in self.disassembly[:max_lines]:
            insn_str = f"{mnemonic:<8s} {op_str}"
            if len(insn_str) > 20:
                insn_str = insn_str[:20]
            else:
                insn_str = insn_str.ljust(20)

            hits = self.coverage_map.hot_addresses.get(addr, 0)

            if hits > 0:
                # Scale brightness: more hits = brighter green
                ratio = hits / max_hits
                if ratio > 0.8:
                    color = "bold bright_green"
                elif ratio > 0.4:
                    color = "green"
                else:
                    color = "dim green"
                lines.append(
                    f"  [{color}]0x{addr:08x} | {insn_str} | {hits:>5d}[/{color}]"
                )
            else:
                lines.append(
                    f"  [red]0x{addr:08x} | {insn_str} |     0[/red]"
                )

        if len(self.disassembly) > max_lines:
            remaining = len(self.disassembly) - max_lines
            lines.append(f"\n  [dim]... {remaining} more instructions[/dim]")

        # Hot spots
        if stats["hot_spots"]:
            lines.append("")
            lines.append("[bold cyan]Top Hot Spots[/bold cyan]")
            for addr, count in stats["hot_spots"]:
                lines.append(f"  [bold green]0x{addr:08x}[/bold green]: {count} hits")

        return "\n".join(lines)

    def render_html(self) -> str:
        """Render an HTML coverage report using the Jinja2 template.

        Returns:
            Complete HTML string.
        """
        env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )
        template = env.get_template("coverage.html.j2")

        stats = self.get_stats()
        max_hits = max(self.coverage_map.hot_addresses.values()) if self.coverage_map.hot_addresses else 1

        # Build instruction data for template
        instructions = []
        for addr, mnemonic, op_str in self.disassembly:
            hits = self.coverage_map.hot_addresses.get(addr, 0)
            ratio = hits / max_hits if max_hits > 0 else 0
            instructions.append({
                "address": f"0x{addr:08x}",
                "address_int": addr,
                "mnemonic": mnemonic,
                "op_str": op_str,
                "hits": hits,
                "ratio": ratio,
            })

        return template.render(
            stats=stats,
            instructions=instructions,
            hot_spots=stats["hot_spots"],
        )

    def write_html(self, path: str) -> None:
        """Render and write the HTML report to a file.

        Args:
            path: Output file path.
        """
        html = self.render_html()
        # Atomic write: write to temp then rename
        tmp_path = path + ".tmp"
        with open(tmp_path, "w") as f:
            f.write(html)
        os.replace(tmp_path, path)

    def get_stats(self) -> dict:
        """Compute coverage statistics.

        Returns:
            Dict with keys: ``total_instructions``, ``covered_instructions``,
            ``coverage_percent``, ``total_edges``, ``hot_spots``.
        """
        hot_sorted = sorted(
            self.coverage_map.hot_addresses.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        hot_spots = hot_sorted[:10]

        return {
            "total_instructions": self.coverage_map.total_instructions,
            "covered_instructions": self.coverage_map.covered_instructions,
            "coverage_percent": self.coverage_map.coverage_percent,
            "total_edges": len(self.coverage_map.covered_edges),
            "hot_spots": hot_spots,
        }
