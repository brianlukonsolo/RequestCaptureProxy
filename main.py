import base64
import html
import json
import os
import socket
import traceback
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import requests
from flask import Flask, Response, make_response, request


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}

VALID_MODES = {"proxy", "idp"}

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


@dataclass
class AppConfig:
    mode: str
    listen_host: str
    listen_port: int
    request_forward_url: str
    response_forward_url: str
    request_entry_path: str
    response_entry_path: str
    preserve_host_header: bool
    request_timeout_seconds: float
    log_dir: Path
    max_body_log_bytes: int
    idp_post_url: str
    idp_saml_response: str
    idp_form_field_name: str
    idp_relay_state: str
    idp_passthrough_relay_state: bool
    idp_extra_form_fields: Dict[str, str]
    idp_set_cookie_name: str
    idp_set_header_name: str
    idp_body_template: str
    idp_http_status: int
    idp_content_type: str


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "t", "yes", "y", "on"}


def env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    return int(raw)


def env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    return float(raw)


def normalize_entry_path(path: str, fallback: str) -> str:
    value = (path or fallback).strip()
    if not value.startswith("/"):
        value = f"/{value}"
    return value.rstrip("/") or "/"


def parse_extra_fields(raw: str) -> Dict[str, str]:
    if not raw:
        return {}
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("IDP_EXTRA_FORM_FIELDS must be a JSON object")
    return {str(k): str(v) for k, v in data.items()}


def load_dotenv_if_present(path: Path = Path(".env")) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ[key] = value


def validate_mode(mode: str) -> str:
    if mode not in VALID_MODES:
        raise ValueError(f"MODE must be one of {sorted(VALID_MODES)}. Got: {mode!r}")
    return mode


def validate_target_url(name: str, value: str) -> None:
    if not value:
        return
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{name} must be an absolute HTTP/HTTPS URL. Got: {value!r}")


def load_config() -> AppConfig:
    mode = validate_mode(os.getenv("MODE", "proxy").strip().lower())
    request_forward_url = os.getenv("REQUEST_FORWARD_URL", "").strip()
    response_forward_url = os.getenv("RESPONSE_FORWARD_URL", "").strip()
    validate_target_url("REQUEST_FORWARD_URL", request_forward_url)
    validate_target_url("RESPONSE_FORWARD_URL", response_forward_url)

    request_entry_path = normalize_entry_path(os.getenv("REQUEST_ENTRY_PATH", ""), "/forward/request")
    response_entry_path = normalize_entry_path(os.getenv("RESPONSE_ENTRY_PATH", ""), "/forward/response")
    if request_entry_path == response_entry_path:
        raise ValueError("REQUEST_ENTRY_PATH and RESPONSE_ENTRY_PATH must be different.")

    max_body_log_bytes = env_int("MAX_BODY_LOG_BYTES", 128 * 1024)
    if max_body_log_bytes <= 0:
        raise ValueError("MAX_BODY_LOG_BYTES must be greater than zero.")

    timeout_seconds = env_float("REQUEST_TIMEOUT_SECONDS", 30.0)
    if timeout_seconds <= 0:
        raise ValueError("REQUEST_TIMEOUT_SECONDS must be greater than zero.")

    try:
        extra_form_fields = parse_extra_fields(os.getenv("IDP_EXTRA_FORM_FIELDS", "").strip())
    except ValueError as exc:
        raise ValueError(f"Invalid IDP_EXTRA_FORM_FIELDS: {exc}") from exc

    log_dir = Path(os.getenv("LOG_DIR", "logs"))
    log_dir.mkdir(parents=True, exist_ok=True)
    return AppConfig(
        mode=mode,
        listen_host=os.getenv("LISTEN_HOST", "0.0.0.0"),
        listen_port=env_int("LISTEN_PORT", 8080),
        request_forward_url=request_forward_url,
        response_forward_url=response_forward_url,
        request_entry_path=request_entry_path,
        response_entry_path=response_entry_path,
        preserve_host_header=env_bool("PRESERVE_HOST_HEADER", False),
        request_timeout_seconds=timeout_seconds,
        log_dir=log_dir,
        max_body_log_bytes=max_body_log_bytes,
        idp_post_url=os.getenv("IDP_POST_URL", "").strip(),
        idp_saml_response=os.getenv("IDP_SAML_RESPONSE", "").strip(),
        idp_form_field_name=os.getenv("IDP_FORM_FIELD_NAME", "SAMLResponse").strip(),
        idp_relay_state=os.getenv("IDP_RELAY_STATE", "").strip(),
        idp_passthrough_relay_state=env_bool("IDP_PASSTHROUGH_RELAY_STATE", True),
        idp_extra_form_fields=extra_form_fields,
        idp_set_cookie_name=os.getenv("IDP_SET_COOKIE_NAME", "").strip(),
        idp_set_header_name=os.getenv("IDP_SET_HEADER_NAME", "").strip(),
        idp_body_template=os.getenv("IDP_BODY_TEMPLATE", "").strip(),
        idp_http_status=env_int("IDP_HTTP_STATUS", 200),
        idp_content_type=os.getenv("IDP_CONTENT_TYPE", "text/html; charset=utf-8").strip(),
    )

load_dotenv_if_present()
CONFIG = load_config()
HTTP = requests.Session()
APP = Flask(__name__)


class RequestFileLog:
    def __init__(self, config: AppConfig, request_id: str):
        self.file_path = config.log_dir / f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}_{request_id}.log"
        self._file = self.file_path.open("w", encoding="utf-8")

    def line(self, message: str = "") -> None:
        self._file.write(f"{message}\n")
        self._file.flush()

    def section(self, title: str) -> None:
        self.line()
        self.line("=" * 40)
        self.line(title)
        self.line("=" * 40)

    def close(self) -> None:
        self._file.close()


def format_headers(headers: Iterable[Tuple[str, str]]) -> List[str]:
    items = [(k, v) for k, v in headers]
    if not items:
        return ["(none)"]
    return [f"{k}: {v}" for k, v in items]


def first_header_value(headers: Iterable[Tuple[str, str]], header_name: str) -> str:
    needle = header_name.lower()
    for key, value in headers:
        if key.lower() == needle:
            return value
    return ""


def body_preview(content_type: str, body: bytes, max_bytes: int) -> str:
    if not body:
        return "(empty)"
    truncated = body[:max_bytes]
    cut = len(body) > len(truncated)
    normalized_ct = (content_type or "").lower()
    is_text = any(normalized_ct.startswith(prefix) for prefix in TEXT_LIKE_CONTENT_TYPES)

    if is_text:
        try:
            preview = truncated.decode("utf-8")
        except UnicodeDecodeError:
            preview = truncated.decode("utf-8", errors="replace")
    else:
        preview = f"(base64) {base64.b64encode(truncated).decode('ascii')}"
    if cut:
        preview += f"\n... TRUNCATED {len(body) - len(truncated)} BYTES ..."
    return preview


def parse_attachments(content_type: str, body: bytes, max_bytes: int) -> List[Dict[str, str]]:
    if "multipart/" not in (content_type or "").lower() or not body:
        return []

    try:
        raw = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + body
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:
        return []

    attachments: List[Dict[str, str]] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True) or b""
        disposition = part.get("Content-Disposition", "")
        filename = part.get_filename() or ""
        content_id = part.get("Content-ID", "")
        is_attachment = bool(filename) or "attachment" in disposition.lower() or bool(content_id)
        if not is_attachment:
            continue
        attachments.append(
            {
                "filename": filename or "(none)",
                "content_type": part.get_content_type(),
                "size_bytes": str(len(payload)),
                "content_id": content_id or "(none)",
                "content_preview": body_preview(part.get_content_type(), payload, max_bytes),
            }
        )
    return attachments


def log_message_block(log: RequestFileLog, title: str, method: str, url: str, headers, body: bytes, status: int = 0) -> None:
    header_items = list(headers)
    log.section(title)
    if status:
        log.line(f"Status: {status}")
    log.line(f"Method: {method}")
    log.line(f"URL: {url}")
    log.line(f"Body-Bytes: {len(body)}")
    log.line("Headers:")
    for line in format_headers(header_items):
        log.line(f"  {line}")
    content_type = first_header_value(header_items, "Content-Type")
    attachments = parse_attachments(content_type, body, CONFIG.max_body_log_bytes)
    if attachments:
        log.line("Attachments:")
        for idx, item in enumerate(attachments, start=1):
            log.line(
                f"  [{idx}] filename={item['filename']} content_type={item['content_type']} "
                f"size_bytes={item['size_bytes']} content_id={item['content_id']}"
            )
            log.line("    content_preview:")
            for preview_line in item["content_preview"].splitlines():
                log.line(f"      {preview_line}")
    log.line("Body:")
    for line in body_preview(content_type, body, CONFIG.max_body_log_bytes).splitlines():
        log.line(f"  {line}")


def remove_hop_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}


def join_target_url(base_url: str, suffix_path: str, query_string: bytes) -> str:
    parsed = urlparse(base_url)
    base_path = parsed.path.rstrip("/")
    append_path = suffix_path if suffix_path.startswith("/") else f"/{suffix_path}"
    combined = f"{base_path}{append_path}" if append_path != "/" else (base_path or "/")
    incoming_query = query_string.decode("latin-1")
    merged_query = "&".join([item for item in [parsed.query, incoming_query] if item])
    return urlunparse(parsed._replace(path=combined or "/", query=merged_query))


def strip_entry_prefix(full_path: str, entry_path: str) -> Optional[str]:
    if full_path == entry_path:
        return "/"
    prefix = f"{entry_path}/"
    if full_path.startswith(prefix):
        return full_path[len(entry_path) :] or "/"
    return None


def upstream_header_items(upstream: requests.Response) -> List[Tuple[str, str]]:
    raw_headers = getattr(getattr(upstream, "raw", None), "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "items"):
        return [(str(k), str(v)) for k, v in raw_headers.items()]
    return [(str(k), str(v)) for k, v in upstream.headers.items()]


def build_downstream_response(upstream: requests.Response, header_items: Iterable[Tuple[str, str]]) -> Response:
    response = Response(status=upstream.status_code)
    response.set_data(upstream.content)
    response.headers.pop("Content-Type", None)
    response.headers.pop("Content-Length", None)
    for key, value in header_items:
        lowered = key.lower()
        if lowered in HOP_BY_HOP_HEADERS or lowered == "content-length":
            continue
        response.headers.add(key, value)
    return response


def resolve_forward_target(path: str) -> Tuple[str, str]:
    full_path = f"/{path}" if path else "/"
    remainder = strip_entry_prefix(full_path, CONFIG.request_entry_path)
    if remainder is not None:
        return CONFIG.request_forward_url, remainder
    remainder = strip_entry_prefix(full_path, CONFIG.response_entry_path)
    if remainder is not None:
        return CONFIG.response_forward_url, remainder
    return CONFIG.request_forward_url, full_path


def render_idp_body(default_html: str, fields: Dict[str, str], relay_state: str) -> str:
    if not CONFIG.idp_body_template:
        return default_html
    template = CONFIG.idp_body_template
    replacements = {
        "{{SAML_RESPONSE}}": CONFIG.idp_saml_response,
        "{{POST_URL}}": CONFIG.idp_post_url,
        "{{FORM_FIELD_NAME}}": CONFIG.idp_form_field_name,
        "{{RELAY_STATE}}": relay_state,
        "{{FORM_FIELDS_JSON}}": json.dumps(fields, ensure_ascii=False),
    }
    for key, value in replacements.items():
        template = template.replace(key, value)
    return template


def printable_host(host: str) -> str:
    if host == "0.0.0.0":
        return "localhost"
    if host == "::":
        return "localhost"
    return host


def startup_lines() -> List[str]:
    external_host = printable_host(CONFIG.listen_host)
    lines = [
        "[startup] service=request-capture-proxy",
        f"[startup] mode={CONFIG.mode}",
        f"[startup] bind={CONFIG.listen_host}:{CONFIG.listen_port}",
        f"[startup] local_url=http://{external_host}:{CONFIG.listen_port}",
        f"[startup] health_url=http://{external_host}:{CONFIG.listen_port}/healthz",
        f"[startup] request_entry_path={CONFIG.request_entry_path}",
        f"[startup] response_entry_path={CONFIG.response_entry_path}",
        f"[startup] request_forward_url={CONFIG.request_forward_url or '(not set)'}",
        f"[startup] response_forward_url={CONFIG.response_forward_url or '(not set)'}",
        f"[startup] log_dir={CONFIG.log_dir}",
    ]
    if CONFIG.mode == "idp":
        lines.extend(
            [
                f"[startup] idp_post_url={CONFIG.idp_post_url or '(not set)'}",
                f"[startup] idp_form_field_name={CONFIG.idp_form_field_name}",
                f"[startup] idp_cookie_name={CONFIG.idp_set_cookie_name or '(not set)'}",
                f"[startup] idp_header_name={CONFIG.idp_set_header_name or '(not set)'}",
            ]
        )
    try:
        hostname = socket.gethostname()
        lines.append(f"[startup] container_hostname={hostname}")
    except Exception:
        pass
    return lines


def handle_idp_mode(log: RequestFileLog, request_id: str, inbound_body: bytes) -> Response:
    if not CONFIG.idp_post_url:
        return make_response("IDP mode is enabled but IDP_POST_URL is empty.", 500)
    if not CONFIG.idp_saml_response:
        return make_response("IDP mode is enabled but IDP_SAML_RESPONSE is empty.", 500)

    relay_state = CONFIG.idp_relay_state
    if CONFIG.idp_passthrough_relay_state:
        relay_state = request.values.get("RelayState", relay_state)

    fields = dict(CONFIG.idp_extra_form_fields)
    fields[CONFIG.idp_form_field_name] = CONFIG.idp_saml_response
    if relay_state:
        fields["RelayState"] = relay_state

    hidden_inputs = "\n".join(
        f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}" />'
        for k, v in fields.items()
    )
    default_html = (
        "<!doctype html><html><body>"
        f'<form id="saml_form" method="post" action="{html.escape(CONFIG.idp_post_url)}">'
        f"{hidden_inputs}"
        "</form>"
        "<script>document.getElementById('saml_form').submit();</script>"
        "</body></html>"
    )

    response_body = render_idp_body(default_html, fields, relay_state)

    response = make_response(response_body, CONFIG.idp_http_status)
    response.headers["Content-Type"] = CONFIG.idp_content_type
    if CONFIG.idp_set_cookie_name:
        response.set_cookie(CONFIG.idp_set_cookie_name, CONFIG.idp_saml_response)
    if CONFIG.idp_set_header_name:
        response.headers[CONFIG.idp_set_header_name] = CONFIG.idp_saml_response

    log_message_block(
        log=log,
        title=f"REQUEST START [{request_id}]",
        method=request.method,
        url=request.url,
        headers=request.headers.items(),
        body=inbound_body,
    )
    log_message_block(
        log=log,
        title=f"RESPONSE END [{request_id}] (IDP STATIC)",
        method=request.method,
        url=request.url,
        headers=response.headers.items(),
        body=response_body.encode("utf-8"),
        status=CONFIG.idp_http_status,
    )
    return response


@APP.get("/healthz")
def healthz():
    return {"status": "ok", "mode": CONFIG.mode}


@APP.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
@APP.route("/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def capture_proxy(path: str) -> Response:
    request_id = uuid.uuid4().hex[:12]
    log = RequestFileLog(CONFIG, request_id)
    inbound_body = request.get_data(cache=True)
    started_at = datetime.now(timezone.utc).isoformat()
    log.line(f"request_id={request_id}")
    log.line(f"started_at={started_at}")
    log.line(f"mode={CONFIG.mode}")

    try:
        if CONFIG.mode == "idp":
            return handle_idp_mode(log, request_id, inbound_body)
        if CONFIG.mode != "proxy":
            return make_response(f"Unsupported MODE: {CONFIG.mode}", 500)

        target_base_url, path_suffix = resolve_forward_target(path)
        if not target_base_url:
            msg = (
                "No forward target matched. Set REQUEST_FORWARD_URL and/or RESPONSE_FORWARD_URL, "
                f"and call paths under {CONFIG.request_entry_path} or {CONFIG.response_entry_path}."
            )
            return make_response(msg, 500)

        target_url = join_target_url(target_base_url, path_suffix, request.query_string)
        outbound_headers = {k: v for k, v in request.headers.items()}
        if not CONFIG.preserve_host_header:
            outbound_headers.pop("Host", None)
        outbound_headers = remove_hop_headers(outbound_headers)
        outbound_headers.pop("Content-Length", None)

        log_message_block(
            log=log,
            title=f"REQUEST START [{request_id}]",
            method=request.method,
            url=request.url,
            headers=request.headers.items(),
            body=inbound_body,
        )
        log_message_block(
            log=log,
            title=f"FORWARDED REQUEST [{request_id}]",
            method=request.method,
            url=target_url,
            headers=outbound_headers.items(),
            body=inbound_body,
        )

        upstream = HTTP.request(
            method=request.method,
            url=target_url,
            headers=outbound_headers,
            data=inbound_body,
            timeout=CONFIG.request_timeout_seconds,
            allow_redirects=False,
        )
        upstream_headers = upstream_header_items(upstream)

        log_message_block(
            log=log,
            title=f"RESPONSE END [{request_id}]",
            method=request.method,
            url=target_url,
            headers=upstream_headers,
            body=upstream.content,
            status=upstream.status_code,
        )

        return build_downstream_response(upstream, upstream_headers)
    except requests.RequestException as exc:
        log.section(f"ERROR [{request_id}]")
        log.line(str(exc))
        return make_response(f"Forwarding failed: {exc}", 502)
    except Exception:
        log.section(f"ERROR [{request_id}]")
        log.line(traceback.format_exc())
        return make_response("Unhandled server error.", 500)
    finally:
        log.line()
        log.line(f"finished_at={datetime.now(timezone.utc).isoformat()}")
        log.close()


if __name__ == "__main__":
    print("=" * 72)
    for line in startup_lines():
        print(line)
    print("=" * 72)
    APP.run(host=CONFIG.listen_host, port=CONFIG.listen_port, use_reloader=False)
