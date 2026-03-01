"""RTOSploit — RTOS Exploitation & Bare-Metal Fuzzing Framework."""

try:
    from importlib.metadata import version
    __version__ = version("rtosploit")
except Exception:
    from pathlib import Path
    __version__ = (Path(__file__).resolve().parent.parent / "VERSION").read_text().strip()
