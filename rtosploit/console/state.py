"""Console state management."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class ConsoleState:
    """Tracks current console session state."""

    # Current active module (e.g. "freertos/heap_overflow")
    current_module: Optional[str] = None
    current_module_instance: Optional[Any] = None

    # Option values set by user (key -> value string)
    option_values: dict[str, str] = field(default_factory=dict)

    # Active QEMU instances (PID -> instance)
    active_qemu: dict[int, Any] = field(default_factory=dict)

    # Last scan result
    last_result: Optional[Any] = None

    # History of commands executed
    command_history: list[str] = field(default_factory=list)

    def get_prompt(self) -> str:
        """Return the current prompt string."""
        if self.current_module:
            return f"rtosploit({self.current_module})> "
        return "rtosploit> "

    def set_module(self, module_path: str, instance: Any) -> None:
        """Set the current active module."""
        self.current_module = module_path
        self.current_module_instance = instance
        self.option_values = {}  # Reset options for new module

    def clear_module(self) -> None:
        """Deselect current module."""
        self.current_module = None
        self.current_module_instance = None
        self.option_values = {}

    def cleanup(self) -> None:
        """Stop all active QEMU instances."""
        for pid, instance in list(self.active_qemu.items()):
            try:
                instance.stop()
            except Exception as e:
                logger.warning("Failed to stop QEMU instance %d: %s", pid, e)
        self.active_qemu.clear()
