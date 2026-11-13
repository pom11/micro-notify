"""One-shot HTTPS webhook receiver for the container proof (card MN-P01).

The container proof has to show that a real ``mnotify teams send`` puts a real
HTTP POST on the wire from inside the Alpine image, without a real channel
behind it. This module is that channel: a stdlib ``http.server`` wrapped in a
TLS context, listening on the CI runner, that accepts exactly one POST, records
what arrived, and exits.

Deliberate properties:

* stdlib only (``http.server`` + ``ssl``). No dependency enters the product and
  nothing here is importable from ``micro_notify`` — this file lives under
  ``packaging/docker/ci/``, outside ``src/``, and is not packaged.
* TLS, not plain HTTP. The product sends to an ``https://`` webhook URL and the
  proof must exercise that path; the certificate the container trusts is the
  public half only, and the private key never leaves the runner (it is never
  mounted into the container, never printed, never copied).
* one request, then done. It replies ``202`` — a Workflows hook answers 200/201/
  202 and the product treats any 2xx as success (``teams.post_card``) — writes
  the raw body plus the content type to a file the job can read, and shuts down.
* it never echoes the body to its own stdout beyond a fixed marker, so the CI
  log shows what was received by reading the recorded file, not by trusting the
  server's transcript.

Usage (on the runner):

    python3 stub_webhook.py --cert cert.pem --key key.pem \
        --port 8443 --out received.json

Exits 0 after one POST was recorded, 1 on the deadline, 2 on a bad request line.
"""

from __future__ import annotations

import argparse
import http.server
import json
import ssl
import sys
import threading
from pathlib import Path

RECEIVED_MARKER = "stub-webhook: received one POST"


class StubHandler(http.server.BaseHTTPRequestHandler):
    """Records the one POST it accepts and answers 202 (a Workflows hook's OK)."""

    # Set by ``serve`` before the server starts accepting.
    out_path: Path
    done: threading.Event

    # The default header would print a Python version banner into the CI log;
    # an honest empty server string keeps the log about the product, not the stub.
    server_version = "mnotify-ci-stub"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - base-class parameter name
        """Route the access log to stderr so the job log shows the request happened."""
        sys.stderr.write(f"stub: {format % args}\n")

    def do_POST(self) -> None:  # noqa: N802 - http.server names the method
        """Write raw body + content type to ``out_path`` and reply 202."""
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        record = {
            "path": self.path,
            "content_type": self.headers.get("Content-Type", ""),
            "content_length": length,
            "body": body.decode("utf-8", "replace"),
        }
        self.out_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        payload = b'{"result":"acknowledged"}\n'
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        sys.stderr.write(f"{RECEIVED_MARKER} {self.path}\n")
        sys.stderr.flush()
        self.done.set()

    def do_GET(self) -> None:  # noqa: N802 - http.server names the method
        """Health probe for the job, so it can wait for readiness without a POST."""
        payload = b'{"ok":true}\n'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def serve(cert: Path, key: Path, port: int, out: Path, timeout: float) -> int:
    """Serve HTTPS on 127.0.0.1:``port`` until one POST is recorded.

    ``serve_forever`` runs on its own thread: the accept loop has to run while
    the main thread waits for the event, or a client connection just sits in the
    listen backlog and the job hangs.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))

    done = threading.Event()
    handler = type("BoundStubHandler", (StubHandler,), {"out_path": out, "done": done})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    server.daemon_threads = True
    server.socket = context.wrap_socket(server.socket, server_side=True)

    acceptor = threading.Thread(target=server.serve_forever, daemon=True)
    acceptor.start()
    try:
        finished = done.wait(timeout)
    finally:
        server.shutdown()
        server.server_close()
    if not finished:
        sys.stderr.write(f"stub: no POST recorded within {timeout}s\n")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="one-shot HTTPS webhook stub for CI")
    parser.add_argument("--cert", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args(argv)

    for path, label in ((args.cert, "certificate"), (args.key, "private key")):
        if not path.is_file():
            sys.stderr.write(f"stub: {label} not found at {path}\n")
            return 2
    args.out.parent.mkdir(parents=True, exist_ok=True)
    if args.out.exists():
        args.out.unlink()
    return serve(args.cert, args.key, args.port, args.out, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
