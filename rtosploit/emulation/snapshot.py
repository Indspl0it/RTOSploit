"""VM snapshot management for QEMU instances."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from rtosploit.errors import OperationError

if TYPE_CHECKING:
    from rtosploit.emulation.qemu import QEMUInstance


class SnapshotManager:
    """Manages QEMU VM snapshots via QMP.

    Snapshots allow saving and restoring the complete VM state (CPU registers,
    memory, device state) for rapid fuzzing resets.
    """

    def __init__(self, index_path: Optional[str] = None) -> None:
        """Initialize the snapshot manager.

        Args:
            index_path: Optional path to a JSON file for storing snapshot metadata.
                        If None, metadata is only stored in QEMU's internal state.
        """
        self._index_path = Path(index_path) if index_path else None
        self._metadata: dict[str, dict[str, Any]] = {}
        if self._index_path and self._index_path.exists():
            self._load_index()

    def _load_index(self) -> None:
        """Load snapshot metadata index from disk."""
        try:
            with self._index_path.open() as f:  # type: ignore[union-attr]
                self._metadata = json.load(f)
        except (json.JSONDecodeError, OSError):
            self._metadata = {}

    def _save_index(self) -> None:
        """Persist snapshot metadata index to disk."""
        if self._index_path is None:
            return
        self._index_path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write using a temp file
        tmp = self._index_path.with_suffix(".tmp")
        with tmp.open("w") as f:
            json.dump(self._metadata, f, indent=2)
        tmp.rename(self._index_path)

    def save(self, qemu: "QEMUInstance", name: str) -> None:
        """Save a VM snapshot.

        Pauses the VM, saves the snapshot, then resumes execution.

        Args:
            qemu: Running QEMUInstance.
            name: Snapshot name (must be a valid QEMU snapshot name).
        """
        # Pause first to ensure consistent state
        try:
            qemu.pause()
        except Exception:
            pass  # Already paused is fine

        try:
            # savevm is an HMP command — run it via QMP's human-monitor-command
            result = qemu.qmp.execute(
                "human-monitor-command",
                {"command-line": f"savevm {name}"},
            )
            # human-monitor-command returns a string; non-empty means error
            if isinstance(result, str) and result.strip():
                raise OperationError(f"savevm error: {result.strip()}")
        except OperationError:
            try:
                qemu.resume()
            except Exception:
                pass
            raise
        except Exception as e:
            # Resume before re-raising
            try:
                qemu.resume()
            except Exception:
                pass
            raise OperationError(f"Failed to save snapshot '{name}': {e}") from e

        # Resume execution
        try:
            qemu.resume()
        except Exception:
            pass

        # Store metadata
        self._metadata[name] = {
            "name": name,
            "timestamp": time.time(),
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self._save_index()

    def load(self, qemu: "QEMUInstance", name: str) -> None:
        """Load a VM snapshot.

        Args:
            qemu: Running QEMUInstance.
            name: Name of the snapshot to restore.

        Raises:
            OperationError: If the snapshot doesn't exist or load fails.
        """
        try:
            result = qemu.qmp.execute(
                "human-monitor-command",
                {"command-line": f"loadvm {name}"},
            )
            if isinstance(result, str) and result.strip():
                raise OperationError(f"loadvm error: {result.strip()}")
        except OperationError:
            raise
        except Exception as e:
            raise OperationError(f"Failed to load snapshot '{name}': {e}") from e

    def list_snapshots(self, qemu: "QEMUInstance") -> list[dict[str, Any]]:
        """List all available snapshots for the current QEMU instance.

        Args:
            qemu: Running QEMUInstance.

        Returns:
            List of snapshot info dicts (from QEMU's query-snapshots).
        """
        try:
            result = qemu.qmp.execute("query-snapshots")
            if not isinstance(result, list):
                return []

            # Enrich with our metadata if available
            snapshots = []
            for snap in result:
                snap_name = snap.get("name", "")
                if snap_name in self._metadata:
                    snap["rtosploit_metadata"] = self._metadata[snap_name]
                snapshots.append(snap)

            return snapshots
        except Exception as e:
            raise OperationError(f"Failed to list snapshots: {e}") from e

    def delete(self, qemu: "QEMUInstance", name: str) -> None:
        """Delete a VM snapshot.

        Args:
            qemu: Running QEMUInstance.
            name: Name of the snapshot to delete.
        """
        try:
            result = qemu.qmp.execute(
                "human-monitor-command",
                {"command-line": f"delvm {name}"},
            )
            if isinstance(result, str) and result.strip():
                raise OperationError(f"delvm error: {result.strip()}")
        except OperationError:
            raise
        except Exception as e:
            raise OperationError(f"Failed to delete snapshot '{name}': {e}") from e

        # Remove from metadata index
        self._metadata.pop(name, None)
        self._save_index()

    def fast_reset(self, qemu: "QEMUInstance", snapshot_name: str) -> None:
        """Rapidly reset the VM to a snapshot with minimal latency.

        Sends loadvm immediately followed by cont in a single batch to
        minimize the reset window.

        Args:
            qemu: Running QEMUInstance.
            snapshot_name: Name of the snapshot to restore.
        """
        # Send loadvm via HMP — this implicitly stops the VM
        try:
            result = qemu.qmp.execute(
                "human-monitor-command",
                {"command-line": f"loadvm {snapshot_name}"},
            )
            if isinstance(result, str) and result.strip():
                raise OperationError(f"loadvm error: {result.strip()}")
        except OperationError:
            raise
        except Exception as e:
            raise OperationError(
                f"fast_reset: failed to load snapshot '{snapshot_name}': {e}"
            ) from e

        # Immediately continue execution
        try:
            qemu.qmp.execute("cont")
        except Exception as e:
            raise OperationError(
                f"fast_reset: failed to resume after loading '{snapshot_name}': {e}"
            ) from e
