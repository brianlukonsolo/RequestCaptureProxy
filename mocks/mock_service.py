import base64
import os
import socket
from datetime import datetime, timezone
from typing import Dict, List

from flask import Flask, Response, jsonify, make_response, request


APP = Flask(__name__)
SERVICE_NAME = os.getenv("SERVICE_NAME", "mock-upstream")
LISTEN_HOST = os.getenv("MOCK_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("MOCK_LISTEN_PORT", "18081"))

# 1x1 transparent PNG
PNG_1X1_BASE64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO7+W7sAAAAASUVORK5CYII="
)


def header_items() -> List[Dict[str, str]]:
    return [{"name": key, "value": value} for key, value in request.headers.items()]


def body_snapshot() -> Dict[str, str]:
    payload = request.get_data(cache=True)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    return {
        "size_bytes": str(len(payload)),
        "text": text,
        "base64": base64.b64encode(payload).decode("ascii"),
    }


def request_snapshot() -> Dict:
    return {
        "service": SERVICE_NAME,
        "received_at": datetime.now(timezone.utc).isoformat(),
        "method": request.method,
        "path": request.path,
        "query_string": request.query_string.decode("latin-1"),
        "args": {key: request.args.getlist(key) for key in request.args.keys()},
        "headers": header_items(),
        "body": body_snapshot(),
        "form": request.form.to_dict(flat=False),
    }


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
        f"[startup] binary_example=http://{host}:{LISTEN_PORT}/image/png",
        f"[startup] dup_header_example=http://{host}:{LISTEN_PORT}/response-headers?Set-Cookie=a%3D1&Set-Cookie=b%3D2",
    ]
    try:
        lines.append(f"[startup] container_hostname={socket.gethostname()}")
    except Exception:
        pass
    return lines


@APP.get("/healthz")
def healthz():
    return {"status": "ok", "service": SERVICE_NAME}


@APP.route("/image/png", methods=["GET", "HEAD"])
def image_png():
    data = base64.b64decode(PNG_1X1_BASE64)
    response = Response(data, status=200, content_type="image/png")
    response.headers["X-Mock-Service"] = SERVICE_NAME
    return response


@APP.route("/response-headers", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def response_headers():
    status_code = 200
    if request.args.get("status"):
        try:
            status_code = int(request.args.get("status", "200"))
        except ValueError:
            status_code = 400
    payload = request_snapshot()
    response = make_response(jsonify(payload), status_code)
    for key in request.args.keys():
        for value in request.args.getlist(key):
            if key.lower() == "status":
                continue
            response.headers.add(key, value)
    response.headers.add("X-Mock-Service", SERVICE_NAME)
    return response


@APP.route("/status/<int:status_code>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def status_code(status_code: int):
    response = make_response(jsonify(request_snapshot()), status_code)
    response.headers["X-Mock-Service"] = SERVICE_NAME
    return response


@APP.route("/set-cookies", methods=["GET", "POST"])
def set_cookies():
    response = make_response(jsonify(request_snapshot()), 200)
    response.set_cookie("mockA", "1")
    response.set_cookie("mockB", "2")
    response.headers["X-Mock-Service"] = SERVICE_NAME
    return response


@APP.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@APP.route("/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def echo(path: str):
    _ = path
    response = make_response(jsonify(request_snapshot()), 200)
    response.headers["X-Mock-Service"] = SERVICE_NAME
    return response


if __name__ == "__main__":
    print("=" * 72)
    for line in startup_lines():
        print(line)
    print("=" * 72)
    APP.run(host=LISTEN_HOST, port=LISTEN_PORT, use_reloader=False)
