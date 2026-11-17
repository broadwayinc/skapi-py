"""
A small WebSocket client (RFC 6455) on the Python standard library, for skapi-py's realtime
connection: TLS, the opening handshake, masked client frames, ping/pong, fragmented messages and
the closing handshake. Text messages only, which is all the realtime API sends.
"""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import ssl
import struct
import threading
from typing import Optional, Tuple
from urllib.parse import urlsplit

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA


class WebSocketClosed(Exception):
    def __init__(self, code: Optional[int] = None, reason: str = ""):
        super().__init__(f"closed ({code}) {reason}".strip())
        self.code = code
        self.reason = reason


class WebSocket:
    def __init__(self, url: str, timeout: float = 30, headers: Optional[dict] = None):
        parts = urlsplit(url)
        if parts.scheme not in ("ws", "wss"):
            raise ValueError(f"not a websocket url: {url}")
        self.url = url
        host = parts.hostname
        port = parts.port or (443 if parts.scheme == "wss" else 80)
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        raw = socket.create_connection((host, port), timeout=timeout)
        if parts.scheme == "wss":
            raw = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        self.sock = raw
        self._send_lock = threading.Lock()
        self._buffer = b""
        self.closed = False
        self.close_code: Optional[int] = None
        self.close_reason = ""
        self._handshake(host, port, path, parts.scheme, headers or {})
        self.sock.settimeout(None)

    # ---- handshake ------------------------------------------------------------------------------

    def _handshake(self, host: str, port: int, path: str, scheme: str, headers: dict) -> None:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        default_port = 443 if scheme == "wss" else 80
        host_header = host if port == default_port else f"{host}:{port}"
        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host_header}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ] + [f"{k}: {v}" for k, v in headers.items()]
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("utf-8"))
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise WebSocketClosed(None, "connection closed during the handshake")
            response += chunk
        head, _, rest = response.partition(b"\r\n\r\n")
        self._buffer = rest
        status_line, *header_lines = head.decode("latin-1").split("\r\n")
        if " 101 " not in f"{status_line} ":
            raise WebSocketClosed(None, f"handshake refused: {status_line}")
        got = {k.strip().lower(): v.strip() for k, v in (h.split(":", 1) for h in header_lines if ":" in h)}
        expected = base64.b64encode(hashlib.sha1((key + GUID).encode("ascii")).digest()).decode("ascii")
        if got.get("sec-websocket-accept") != expected:
            raise WebSocketClosed(None, "handshake refused: bad Sec-WebSocket-Accept")

    # ---- frames ---------------------------------------------------------------------------------

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        header = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header += bytes([0x80 | n])
        elif n < 65536:
            header += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", n)
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        with self._send_lock:
            if self.closed and opcode != OP_CLOSE:
                raise WebSocketClosed(self.close_code, self.close_reason)
            self.sock.sendall(header + mask + masked)

    def _read_exact(self, n: int) -> bytes:
        while len(self._buffer) < n:
            chunk = self.sock.recv(max(4096, n - len(self._buffer)))
            if not chunk:
                self.closed = True
                raise WebSocketClosed(self.close_code or 1006, "connection lost")
            self._buffer += chunk
        data, self._buffer = self._buffer[:n], self._buffer[n:]
        return data

    def _read_frame(self) -> Tuple[bool, int, bytes]:
        b0, b1 = self._read_exact(2)
        fin, opcode = bool(b0 & 0x80), b0 & 0x0F
        masked, n = bool(b1 & 0x80), b1 & 0x7F
        if n == 126:
            n = struct.unpack(">H", self._read_exact(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", self._read_exact(8))[0]
        mask = self._read_exact(4) if masked else None
        payload = self._read_exact(n)
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return fin, opcode, payload

    # ---- public ---------------------------------------------------------------------------------

    def send(self, text: str) -> None:
        self._send_frame(OP_TEXT, text.encode("utf-8"))

    def recv(self) -> str:
        """The next text message. Answers pings on its own; raises WebSocketClosed when the connection ends."""
        parts = []
        while True:
            fin, opcode, payload = self._read_frame()
            if opcode == OP_PING:
                self._send_frame(OP_PONG, payload)
                continue
            if opcode == OP_PONG:
                continue
            if opcode == OP_CLOSE:
                code = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else 1005
                reason = payload[2:].decode("utf-8", errors="replace")
                if not self.closed:
                    try:
                        self._send_frame(OP_CLOSE, payload[:2])
                    except OSError:
                        pass
                self.closed = True
                self.close_code, self.close_reason = code, reason
                try:
                    self.sock.close()
                except OSError:
                    pass
                raise WebSocketClosed(code, reason)
            if opcode in (OP_TEXT, OP_BINARY, OP_CONT):
                parts.append(payload)
                if fin:
                    return b"".join(parts).decode("utf-8", errors="replace")

    def close(self, code: int = 1000, reason: str = "") -> None:
        if self.closed:
            return
        try:
            self._send_frame(OP_CLOSE, struct.pack(">H", code) + reason.encode("utf-8")[:120])
        except OSError:
            pass
        self.closed = True
        self.close_code, self.close_reason = code, reason
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
