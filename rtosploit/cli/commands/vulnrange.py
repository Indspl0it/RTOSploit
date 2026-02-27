"""rtosploit vulnrange — VulnRange CVE reproduction lab."""
import click
from rich.console import Console
from rich.table import Table
from rich.markdown import Markdown

console = Console()

VULNRANGE_DIR = "vulnrange"


@click.group("vulnrange")
def vulnrange():
    """VulnRange — CVE reproduction lab for RTOS vulnerabilities."""
    pass


@vulnrange.command("list")
@click.pass_context
def vulnrange_list(ctx):
    """List all available CVE ranges."""
    from rtosploit.vulnrange.manager import VulnRangeManager
    mgr = VulnRangeManager(VULNRANGE_DIR)

    try:
        ranges = mgr.list()
    except Exception:
        ranges = []

    output_json = ctx.obj.get("output_json", False)
    if output_json:
        import json
        serialized = []
        for r in ranges:
            try:
                serialized.append({
                    "id": r.id,
                    "title": r.title,
                    "cve": r.cve,
                    "cvss": r.cvss,
                    "difficulty": r.difficulty,
                    "category": r.category,
                })
            except Exception:
                pass
        click.echo(json.dumps(serialized, indent=2))
        return

    table = Table(title="VulnRange -- CVE Reproduction Lab", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Title", style="white")
    table.add_column("RTOS", style="green")
    table.add_column("Difficulty", style="yellow")
    table.add_column("Category", style="magenta")
    table.add_column("CVSS", style="red")

    for r in ranges:
        try:
            diff = r.difficulty
            diff_color = {"beginner": "green", "intermediate": "yellow", "advanced": "red"}.get(diff, "white")
            title = r.title
            table.add_row(
                r.id,
                title[:45] + "..." if len(title) > 45 else title,
                r.target.rtos,
                f"[{diff_color}]{diff}[/{diff_color}]",
                r.category,
                str(r.cvss) if r.cvss else "N/A",
            )
        except Exception:
            pass

    console.print(table)
    console.print(f"\n[dim]{len(ranges)} ranges available.[/dim]")
    console.print("[dim]Run 'rtosploit vulnrange start <ID>' to begin a challenge.[/dim]")


@vulnrange.command("start")
@click.argument("range_id")
@click.pass_context
def vulnrange_start(ctx, range_id):
    """Start a VulnRange challenge."""
    from rtosploit.vulnrange.manager import VulnRangeManager
    mgr = VulnRangeManager(VULNRANGE_DIR)

    try:
        info = mgr.get_range_info(range_id)
    except FileNotFoundError:
        console.print(f"[red]Range not found: {range_id}[/red]")
        raise SystemExit(1)

    output_json = ctx.obj.get("output_json", False)
    if output_json:
        import json
        click.echo(json.dumps(info, indent=2))
        return

    from rich.panel import Panel
    console.print(Panel(
        f"[bold]{info['title']}[/bold]\n\n{info.get('description', '')}\n\n"
        f"[bold]CVE:[/bold] {info.get('cve', 'N/A')}  "
        f"[bold]CVSS:[/bold] {info.get('cvss', 'N/A')}  "
        f"[bold]Difficulty:[/bold] {info.get('difficulty', '?')}",
        title=f"[cyan]{range_id}[/cyan]",
        border_style="cyan",
    ))

    console.print("\n[bold]Target:[/bold]")
    console.print(f"  RTOS:    [cyan]{info.get('rtos')} {info.get('rtos_version', '')}[/cyan]")
    console.print(f"  Machine: [cyan]{info.get('machine')}[/cyan]")
    console.print(f"  Exploit: [cyan]{info.get('technique')}[/cyan]")

    if not info.get("firmware_ready"):
        console.print(f"\n[yellow]Note: Firmware binary is a placeholder. Build with: cd vulnrange && make {range_id}[/yellow]")

    console.print("\n[dim]Commands:[/dim]")
    console.print(f"  [dim]rtosploit vulnrange hint {range_id}     -- get a hint[/dim]")
    console.print(f"  [dim]rtosploit vulnrange solve {range_id}    -- run the exploit[/dim]")
    console.print(f"  [dim]rtosploit vulnrange writeup {range_id}  -- read the writeup[/dim]")


@vulnrange.command("hint")
@click.argument("range_id")
@click.option("--level", "-l", type=int, default=1, show_default=True, help="Hint level (1=general, 3=spoiler)")
@click.pass_context
def vulnrange_hint(ctx, range_id, level):
    """Get a progressive hint for a challenge."""
    from rtosploit.vulnrange.manager import VulnRangeManager
    mgr = VulnRangeManager(VULNRANGE_DIR)

    try:
        hint = mgr.hint(range_id, level)
    except FileNotFoundError:
        console.print(f"[red]Range not found: {range_id}[/red]")
        raise SystemExit(1)

    console.print(f"[bold yellow]Hint (level {level}):[/bold yellow] {hint}")


@vulnrange.command("solve")
@click.argument("range_id")
@click.pass_context
def vulnrange_solve(ctx, range_id):
    """Run the reference exploit script for a challenge."""
    from rtosploit.vulnrange.manager import VulnRangeManager
    mgr = VulnRangeManager(VULNRANGE_DIR)

    try:
        exploit_path = mgr.get_exploit_path(range_id)
    except FileNotFoundError:
        console.print(f"[red]Range not found: {range_id}[/red]")
        raise SystemExit(1)

    if not exploit_path.exists():
        console.print(f"[red]Exploit script not found: {exploit_path}[/red]")
        raise SystemExit(1)

    console.print(f"[bold]Running exploit:[/bold] [cyan]{exploit_path}[/cyan]")

    import subprocess, sys
    result = subprocess.run([sys.executable, str(exploit_path)], capture_output=False)

    if result.returncode == 0:
        console.print("\n[green][+] Exploit completed (exit 0)[/green]")
    else:
        console.print(f"\n[yellow][-] Exploit exited with code {result.returncode}[/yellow]")


@vulnrange.command("writeup")
@click.argument("range_id")
@click.pass_context
def vulnrange_writeup(ctx, range_id):
    """Display the writeup for a challenge."""
    from rtosploit.vulnrange.manager import VulnRangeManager
    mgr = VulnRangeManager(VULNRANGE_DIR)

    try:
        writeup_path = mgr.get_writeup_path(range_id)
    except FileNotFoundError:
        console.print(f"[red]Range not found: {range_id}[/red]")
        raise SystemExit(1)

    if not writeup_path.exists():
        console.print(f"[yellow]No writeup available for {range_id}[/yellow]")
        return

    with open(writeup_path) as f:
        content = f.read()

    console.print(Markdown(content))
