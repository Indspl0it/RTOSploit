"""QMP (QEMU Machine Protocol) client for controlling QEMU instances."""

from __future__ import annotations

import json
import socket
import time
from typing import Any, Optional

from rtosploit.errors import QEMUCrashError, OperationError


class QMPClient:
    """Client for the QEMU Machine Protocol over a Unix domain socket.

    QMP is a JSON-based protocol that allows external programs to control
    QEMU instances. Commands are sent as JSON objects and responses are
    received as line-delimited JSON.
    """

    def __init__(self) -> None:
        self._sock: Optional[socket.socket] = None
        self._events: list[dict[str, Any]] = []
        self._connected = False

    def connect(self, socket_path: str, timeout: float = 5.0) -> None:
        """Connect to QEMU QMP socket.

        Retries up to 10 times with 0.5s backoff because QEMU takes time
        to create the socket after process start.

        Args:
            socket_path: Path to the Unix domain socket.
            timeout: Socket timeout in seconds.

        Raises:
            QEMUCrashError: If connection fails after all retries.
        """
        max_retries = 10
        retry_delay = 0.5
        last_error: Optional[Exception] = None

        for attempt in range(max_retries):
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect(socket_path)
                self._sock = sock

                # Read the QMP greeting
                greeting = self._read_response()
                if "QMP" not in greeting and "version" not in str(greeting):
                    # Still accept it — some QEMU versions differ
                    pass

                # Send capabilities negotiation
                self._send_raw({"execute": "qmp_capabilities"})
                response = self._read_response()
                if "error" in response:
                    raise OperationError(
                        f"QMP capabilities negotiation failed: {response['error']}"
                    )

                self._connected = True
                return

            except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
                last_error = e
                if self._sock:
                    try:
                        self._sock.close()
                    except Exception:
                        pass
                    self._sock = None
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)

        raise QEMUCrashError(
            f"Failed to connect to QMP socket '{socket_path}' "
            f"after {max_retries} attempts: {last_error}"
        )

    def _send_raw(self, obj: dict[str, Any]) -> None:
        """Send a JSON object over the socket."""
        if self._sock is None:
            raise OperationError("QMP client is not connected")
        data = json.dumps(obj).encode("utf-8") + b"\n"
        self._sock.sendall(data)

    def _read_response(self) -> dict[str, Any]:
        """Read a single line-delimited JSON response from the socket.

        Handles partial reads by accumulating data until a complete JSON
        object (terminated by newline) is received.

        Returns:
            Parsed JSON response dict.

        Raises:
            OperationError: If the socket is closed or data is malformed.
        """
        if self._sock is None:
            raise OperationError("QMP client is not connected")

        buf = b""
        while True:
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout:
                raise OperationError("Timeout waiting for QMP response")

            if not chunk:
                raise OperationError("QMP socket closed unexpectedly")

            buf += chunk

            # Process all complete lines in the buffer
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError as e:
                    raise OperationError(f"Invalid JSON from QMP: {e}: {line!r}")

                # Events are buffered separately
                if "event" in msg:
                    self._events.append(msg)
                    continue

                return msg

    def execute(self, command: str, arguments: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Send a QMP command and return the response.

        Args:
            command: QMP command name (e.g., "query-status", "savevm").
            arguments: Optional dict of command arguments.

        Returns:
            The "return" value from the QMP response.

        Raises:
            OperationError: If the command returns an error.
        """
        obj: dict[str, Any] = {"execute": command}
        if arguments:
            obj["arguments"] = arguments

        self._send_raw(obj)

        # Read responses, buffering events until we get the command response
        while True:
            response = self._read_response()
            if "return" in response:
                return response["return"]
            if "error" in response:
                err = response["error"]
                raise OperationError(
                    f"QMP command '{command}' failed: "
                    f"{err.get('class', 'Unknown')}: {err.get('desc', str(err))}"
                )
            # Unexpected response format — return it anyway
            return response

    def get_events(self) -> list[dict[str, Any]]:
        """Return and clear the buffered async events received from QEMU.

        Returns:
            List of event dicts (may be empty).
        """
        # Attempt a non-blocking drain of any pending data
        if self._sock is not None:
            self._sock.setblocking(False)
            try:
                while True:
                    chunk = self._sock.recv(4096)
                    if not chunk:
                        break
                    # Parse any events in the chunk
                    for line in chunk.split(b"\n"):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            msg = json.loads(line)
                            if "event" in msg:
                                self._events.append(msg)
                        except json.JSONDecodeError:
                            pass
            except (BlockingIOError, socket.error):
                pass
            finally:
                self._sock.setblocking(True)
                self._sock.settimeout(5.0)

        events = list(self._events)
        self._events.clear()
        return events

    def close(self) -> None:
        """Close the QMP socket connection."""
        self._connected = False
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def __enter__(self) -> "QMPClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
