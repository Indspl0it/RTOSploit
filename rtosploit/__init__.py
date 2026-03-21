"""RTOSploit — RTOS Exploitation & Bare-Metal Fuzzing Framework."""

from pathlib import Path

_version_file = Path(__file__).resolve().parent.parent / "VERSION"
if _version_file.exists():
    __version__ = _version_file.read_text().strip()
else:
    try:
        from importlib.metadata import version
        __version__ = version("rtosploit")
    except Exception:
        __version__ = "2.5.1"
