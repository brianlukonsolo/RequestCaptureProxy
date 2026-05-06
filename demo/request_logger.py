import base64
import json
import os
import socket
import uuid
from datetime import datetime, timezone
from typing import Dict, List

from flask import Flask, Response, jsonify, make_response, request


APP = Flask(__name__)
SERVICE_NAME = os.getenv("SERVICE_NAME", "demo-request-logger")
LISTEN_HOST = os.getenv("DEMO_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("DEMO_LISTEN_PORT", "18080"))
MAX_BODY_LOG_BYTES = int(os.getenv("DEMO_MAX_BODY_LOG_BYTES", "8192"))

TEXT_LIKE_CONTENT_TYPES = (
    "application/json",
    "application/xml",
    "application/x-www-form-urlencoded",
    "application/soap+xml",
    "application/samlassertion+xml",
    "application/samlmetadata+xml",
    "application/xhtml+xml",
    "text/",
    "multipart/",
)


def header_items() -> List[Dict[str, str]]:
    return [{"name": key, "value": value} for key, value in request.headers.items()]


def body_preview(content_type: str, body: bytes) -> str:
    if not body:
        return "(empty)"
    truncated = body[:MAX_BODY_LOG_BYTES]
    cut = len(body) > len(truncated)
    normalized_ct = (content_type or "").lower()
    is_text = any(normalized_ct.startswith(prefix) for prefix in TEXT_LIKE_CONTENT_TYPES)
    if is_text:
        preview = truncated.decode("utf-8", errors="replace")
    else:
        preview = f"(base64) {base64.b64encode(truncated).decode('ascii')}"
    if cut:
        preview += f"\n... TRUNCATED {len(body) - len(truncated)} BYTES ..."
    return preview


def body_snapshot() -> Dict[str, str]:
    payload = request.get_data(cache=True)
    content_type = request.headers.get("Content-Type", "")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    return {
        "size_bytes": str(len(payload)),
        "text": text,
        "base64": base64.b64encode(payload).decode("ascii"),
        "preview": body_preview(content_type, payload),
    }


def request_snapshot(request_id: str) -> Dict:
    return {
        "service": SERVICE_NAME,
        "request_id": request_id,
        "received_at": datetime.now(timezone.utc).isoformat(),
        "method": request.method,
        "url": request.url,
        "path": request.path,
        "query_string": request.query_string.decode("latin-1"),
        "args": {key: request.args.getlist(key) for key in request.args.keys()},
        "headers": header_items(),
        "body": body_snapshot(),
        "form": request.form.to_dict(flat=False),
    }


def log_received_request(snapshot: Dict) -> None:
    print("=" * 72, flush=True)
    print(f"[demo-request] service={SERVICE_NAME}", flush=True)
    print(f"[demo-request] request_id={snapshot['request_id']}", flush=True)
    print(f"[demo-request] received_at={snapshot['received_at']}", flush=True)
    print(f"[demo-request] method={snapshot['method']}", flush=True)
    print(f"[demo-request] url={snapshot['url']}", flush=True)
    print(f"[demo-request] path={snapshot['path']}", flush=True)
    print(f"[demo-request] query_string={snapshot['query_string'] or '(empty)'}", flush=True)
    print("[demo-request] headers:", flush=True)
    for item in snapshot["headers"]:
        print(f"  {item['name']}: {item['value']}", flush=True)
    print("[demo-request] form:", flush=True)
    if snapshot["form"]:
        print(json.dumps(snapshot["form"], indent=2, ensure_ascii=False), flush=True)
    else:
        print("  (empty)", flush=True)
    print(f"[demo-request] body_bytes={snapshot['body']['size_bytes']}", flush=True)
    print("[demo-request] body_preview:", flush=True)
    for line in snapshot["body"]["preview"].splitlines():
        print(f"  {line}", flush=True)
    print("=" * 72, flush=True)


def printable_host(host: str) -> str:
    if host in {"0.0.0.0", "::"}:
        return "localhost"
    return host


def startup_lines() -> List[str]:
    host = printable_host(LISTEN_HOST)
    lines = [
        f"[startup] service={SERVICE_NAME}",
        f"[startup] bind={LISTEN_HOST}:{LISTEN_PORT}",
        f"[startup] local_url=http://{host}:{LISTEN_PORT}",
        f"[startup] health_url=http://{host}:{LISTEN_PORT}/healthz",
        f"[startup] echo_example=http://{host}:{LISTEN_PORT}/anything?x=1",
        f"[startup] logs=stdout",
    ]
    try:
        lines.append(f"[startup] container_hostname={socket.gethostname()}")
    except Exception:
        pass
    return lines


@APP.get("/healthz")
def healthz():
    return {"status": "ok", "service": SERVICE_NAME}


@APP.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@APP.route("/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def log_and_echo(path: str):
    _ = path
    request_id = uuid.uuid4().hex[:12]
    snapshot = request_snapshot(request_id)
    log_received_request(snapshot)
    response = make_response(jsonify(snapshot), 200)
    response.headers["X-Demo-Request-Logger"] = SERVICE_NAME
    return response


if __name__ == "__main__":
    print("=" * 72, flush=True)
    for line in startup_lines():
        print(line, flush=True)
    print("=" * 72, flush=True)
    APP.run(host=LISTEN_HOST, port=LISTEN_PORT, use_reloader=False)
