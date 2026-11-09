#!/usr/bin/env python3
"""Tiny demo application. Logs every request it actually receives, so the demo can
prove that blocked (malicious) requests never reach this instance."""
import json
import os
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("APP_PORT", "80"))
LOG = os.environ.get("APP_LOG", "/var/log/app/access.log")
HOST = socket.gethostname()


class Handler(BaseHTTPRequestHandler):
    server_version = "DemoApp/1.0"

    def _handle(self):
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "client": self.client_address[0],
            "method": self.command,
            "path": self.path,
            "user_agent": self.headers.get("User-Agent", ""),
        }
        try:
            with open(LOG, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass
        body = f"OK - hello from the protected application ({HOST})\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = _handle

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
