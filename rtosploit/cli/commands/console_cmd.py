"""rtosploit console — interactive REPL."""
import click


@click.command("console")
def console_cmd():
    """Launch the interactive RTOSploit console (Metasploit-style REPL).

    \b
    Example:
      rtosploit console
    """
    from rtosploit.console.repl import RTOSploitConsole
    c = RTOSploitConsole()
    c.run()
