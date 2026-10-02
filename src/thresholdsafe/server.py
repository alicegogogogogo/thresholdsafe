from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from .errors import NotFoundError, ThresholdSafeError, ValidationError
from .service import ThresholdSafe


class Handler(BaseHTTPRequestHandler):
    service: ThresholdSafe

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(self, status: int, value: Any) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> Any:
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise ValidationError("Content-Type must be application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 1_000_000:
                raise ValueError
            return json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError) as error:
            raise ValidationError("request body must be valid JSON") from error

    def _dispatch(self) -> tuple[int, Any]:
        parts = [part for part in urlsplit(self.path).path.split("/") if part]
        key = self.headers.get("Idempotency-Key")
        if self.command == "GET" and parts == ["health"]:
            return 200, {"status": "ok"}
        if self.command == "POST" and parts == ["secrets"]:
            return 201, self.service.create_secret(self._body(), key)
        if len(parts) == 2 and parts[0] == "secrets" and self.command == "GET":
            return 200, self.service.get_secret(parts[1])
        if self.command == "POST" and parts == ["backups", "verify"]:
            return 200, self.service.verify_backup(self._body())
        if len(parts) == 3 and parts[0] == "secrets":
            if parts[2] == "audit" and self.command == "GET":
                return 200, self.service.audit(parts[1])
            if parts[2] == "backup" and self.command == "GET":
                return 200, self.service.export_backup(parts[1])
            if self.command == "POST":
                body = self._body()
                actions = {
                    "shares": (201, self.service.distribute_share),
                    "approvals": (201, self.service.record_approval),
                    "reconstruct": (200, self.service.reconstruct),
                    "rotate": (200, self.service.rotate),
                    "freeze": (200, self.service.freeze_secret),
                    "unfreeze": (200, self.service.unfreeze_secret),
                }
                if parts[2] in actions:
                    status, action = actions[parts[2]]
                    return status, action(parts[1], body, key)
        raise NotFoundError("route was not found")

    def _handle(self) -> None:
        try:
            status, response = self._dispatch()
            self._json(status, response)
        except ThresholdSafeError as error:
            self._json(error.status, {"error": {"code": error.code, "message": str(error)}})
        except Exception:
            self._json(500, {"error": {"code": "internal_error", "message": "internal server error"}})

    do_GET = _handle
    do_POST = _handle


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the ThresholdSafe HTTP service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8080, type=int)
    parser.add_argument("--database", default="thresholdsafe.db")
    arguments = parser.parse_args()
    Handler.service = ThresholdSafe(arguments.database)
    server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)
    print(f"ThresholdSafe listening on http://{arguments.host}:{arguments.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
