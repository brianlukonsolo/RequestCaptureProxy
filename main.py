import base64
import html
import json
import os
import socket
import traceback
import uuid
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, urlunparse

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
SAML_SEND_BINDINGS = {"browser_post", "browser_redirect", "server_post"}
SAML_REQUEST_INPUT_FORMATS = {"raw_xml", "encoded"}
SAML_CUSTOM_TARGET_CHOICE = "custom"
SAML_PAYLOAD_FIELD_NAMES = {"SAMLRequest", "SAMLResponse"}
SAML_INSTANCE_SSO_TARGET_CHOICE = "instance:sso"
SAML_INSTANCE_ACS_TARGET_CHOICE = "instance:acs"

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
    saml_instance_sso_path: str
    saml_instance_acs_path: str
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
    saml_request_targets: List[Dict[str, str]]


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


def parse_saml_request_targets(raw: str) -> List[Dict[str, str]]:
    raw = (raw or "").strip()
    if not raw:
        return []

    entries = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = None

    if isinstance(data, dict):
        entries = [{"name": str(name), "url": str(url)} for name, url in data.items()]
    elif isinstance(data, list):
        for idx, item in enumerate(data, start=1):
            if isinstance(item, str):
                entries.append({"name": f"Target {idx}", "url": item})
            elif isinstance(item, dict):
                url = item.get("url", "")
                name = item.get("name", "") or url or f"Target {idx}"
                entries.append({"name": str(name), "url": str(url)})
            else:
                raise ValueError("SAML_REQUEST_TARGETS list items must be strings or objects")
    elif data is not None:
        raise ValueError("SAML_REQUEST_TARGETS must be a JSON object, JSON list, or delimited string")
    else:
        normalized = raw.replace("\r", "\n").replace(";", "\n").replace(",", "\n")
        for idx, item in enumerate([part.strip() for part in normalized.splitlines() if part.strip()], start=1):
            if "=" in item:
                name, url = item.split("=", 1)
                entries.append({"name": name.strip() or f"Target {idx}", "url": url.strip()})
            else:
                entries.append({"name": f"Target {idx}", "url": item})

    targets: List[Dict[str, str]] = []
    for idx, item in enumerate(entries, start=1):
        name = (item.get("name") or f"Target {idx}").strip()
        url = (item.get("url") or "").strip()
        if not url:
            raise ValueError(f"SAML_REQUEST_TARGETS entry {idx} is missing a URL")
        validate_target_url(f"SAML_REQUEST_TARGETS entry {idx}", url)
        targets.append({"name": name or url, "url": url})
    return targets


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
        if not key:
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
    saml_instance_sso_path = normalize_entry_path(os.getenv("SAML_INSTANCE_SSO_PATH", ""), "/saml/instance/sso")
    saml_instance_acs_path = normalize_entry_path(os.getenv("SAML_INSTANCE_ACS_PATH", ""), "/saml/instance/acs")
    route_paths = {
        "REQUEST_ENTRY_PATH": request_entry_path,
        "RESPONSE_ENTRY_PATH": response_entry_path,
        "SAML_INSTANCE_SSO_PATH": saml_instance_sso_path,
        "SAML_INSTANCE_ACS_PATH": saml_instance_acs_path,
    }
    if len(set(route_paths.values())) != len(route_paths):
        raise ValueError("REQUEST_ENTRY_PATH, RESPONSE_ENTRY_PATH, SAML_INSTANCE_SSO_PATH, and SAML_INSTANCE_ACS_PATH must be different.")

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

    try:
        saml_request_targets = parse_saml_request_targets(os.getenv("SAML_REQUEST_TARGETS", "").strip())
    except ValueError as exc:
        raise ValueError(f"Invalid SAML_REQUEST_TARGETS: {exc}") from exc

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
        saml_instance_sso_path=saml_instance_sso_path,
        saml_instance_acs_path=saml_instance_acs_path,
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
        saml_request_targets=saml_request_targets,
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


def append_query_params(url: str, params: Dict[str, str]) -> str:
    parsed = urlparse(url)
    new_query = urlencode(params)
    merged_query = "&".join([item for item in [parsed.query, new_query] if item])
    return urlunparse(parsed._replace(query=merged_query))


def json_response(payload: Dict, status: int = 200) -> Response:
    response = make_response(json.dumps(payload, ensure_ascii=False), status)
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    return response


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
    remainder = strip_entry_prefix(full_path, CONFIG.saml_instance_sso_path)
    if remainder is not None:
        return CONFIG.request_forward_url, remainder
    remainder = strip_entry_prefix(full_path, CONFIG.saml_instance_acs_path)
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


def selected_saml_target(target_choice: str, custom_target_url: str) -> str:
    if target_choice == SAML_INSTANCE_SSO_TARGET_CHOICE:
        target_url = absolute_request_url(CONFIG.saml_instance_sso_path)
    elif target_choice == SAML_INSTANCE_ACS_TARGET_CHOICE:
        target_url = absolute_request_url(CONFIG.saml_instance_acs_path)
    elif target_choice == SAML_CUSTOM_TARGET_CHOICE:
        target_url = custom_target_url.strip()
    elif target_choice.startswith("preset:"):
        try:
            index = int(target_choice.split(":", 1)[1])
        except ValueError as exc:
            raise ValueError("Selected target is invalid.") from exc
        if index < 0 or index >= len(CONFIG.saml_request_targets):
            raise ValueError("Selected target is no longer configured.")
        target_url = CONFIG.saml_request_targets[index]["url"]
    else:
        target_url = target_choice.strip()

    if not target_url:
        raise ValueError("Target URL is required.")
    validate_target_url("Target URL", target_url)
    return target_url


def validate_saml_payload_field_name(field_name: str) -> str:
    value = (field_name or "SAMLRequest").strip()
    if value not in SAML_PAYLOAD_FIELD_NAMES:
        raise ValueError("Payload field must be SAMLRequest or SAMLResponse.")
    return value


def encode_saml_request_payload(raw_value: str, binding: str, input_format: str) -> str:
    value = (raw_value or "").strip()
    if not value:
        raise ValueError("SAML payload is required.")
    if binding not in SAML_SEND_BINDINGS:
        raise ValueError("Unsupported SAML sender binding.")
    if input_format not in SAML_REQUEST_INPUT_FORMATS:
        raise ValueError("Unsupported SAML payload input format.")
    if input_format == "encoded":
        return "".join(value.split())

    source = value.encode("utf-8")
    if binding == "browser_redirect":
        compressor = zlib.compressobj(wbits=-15)
        source = compressor.compress(source) + compressor.flush()
    return base64.b64encode(source).decode("ascii")


def build_saml_send_fields(
    payload_field_name: str,
    encoded_payload: str,
    relay_state: str,
    extra_fields: Dict[str, str],
) -> Dict[str, str]:
    field_name = validate_saml_payload_field_name(payload_field_name)
    fields = {field_name: encoded_payload}
    if relay_state:
        fields["RelayState"] = relay_state
    for key, value in extra_fields.items():
        if key in SAML_PAYLOAD_FIELD_NAMES or key == "RelayState":
            continue
        fields[key] = value
    return fields


def saml_timestamp(offset_seconds: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def xml_escape(value: str) -> str:
    return html.escape(value or "", quote=True)


def sample_authn_request_xml(
    issuer: str,
    destination: str,
    acs_url: str,
    request_id: str = "",
    issue_instant: str = "",
) -> str:
    request_id = request_id or f"_{uuid.uuid4().hex}"
    issue_instant = issue_instant or saml_timestamp()
    issuer = issuer or "https://sp.example.com/metadata"
    destination = destination or "https://idp.example.com/sso"
    acs_url = acs_url or "https://sp.example.com/saml/acs"
    return f"""<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{xml_escape(request_id)}"
    Version="2.0"
    IssueInstant="{xml_escape(issue_instant)}"
    Destination="{xml_escape(destination)}"
    AssertionConsumerServiceURL="{xml_escape(acs_url)}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>{xml_escape(issuer)}</saml:Issuer>
  <samlp:NameIDPolicy
      Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      AllowCreate="true" />
</samlp:AuthnRequest>"""


def sample_saml_response_xml(
    issuer: str,
    destination: str,
    audience: str,
    name_id: str,
    in_response_to: str,
    response_id: str = "",
    assertion_id: str = "",
    issue_instant: str = "",
) -> str:
    response_id = response_id or f"_{uuid.uuid4().hex}"
    assertion_id = assertion_id or f"_{uuid.uuid4().hex}"
    issue_instant = issue_instant or saml_timestamp()
    not_before = saml_timestamp(-60)
    not_on_or_after = saml_timestamp(300)
    issuer = issuer or "https://idp.example.com/metadata"
    destination = destination or "https://sp.example.com/saml/acs"
    audience = audience or "https://sp.example.com/metadata"
    name_id = name_id or "user@example.com"
    in_response_attr = f' InResponseTo="{xml_escape(in_response_to)}"' if in_response_to else ""
    return f"""<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{xml_escape(response_id)}"
    Version="2.0"
    IssueInstant="{xml_escape(issue_instant)}"
    Destination="{xml_escape(destination)}"{in_response_attr}>
  <saml:Issuer>{xml_escape(issuer)}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
  </samlp:Status>
  <saml:Assertion
      ID="{xml_escape(assertion_id)}"
      Version="2.0"
      IssueInstant="{xml_escape(issue_instant)}">
    <saml:Issuer>{xml_escape(issuer)}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{xml_escape(name_id)}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData{in_response_attr}
            NotOnOrAfter="{xml_escape(not_on_or_after)}"
            Recipient="{xml_escape(destination)}" />
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions
        NotBefore="{xml_escape(not_before)}"
        NotOnOrAfter="{xml_escape(not_on_or_after)}">
      <saml:AudienceRestriction>
        <saml:Audience>{xml_escape(audience)}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement
        AuthnInstant="{xml_escape(issue_instant)}"
        SessionIndex="{xml_escape(assertion_id)}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>{xml_escape(name_id)}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""


def build_saml_example_payload(values: Dict[str, str]) -> Dict[str, str]:
    kind = (values.get("kind") or "authn_request").strip()
    issuer = values.get("issuer", "")
    destination = values.get("destination", "")
    acs_url = values.get("acs_url", "")
    audience = values.get("audience", "")
    name_id = values.get("name_id", "")
    in_response_to = values.get("in_response_to", "")

    if kind == "authn_request":
        return {
            "kind": kind,
            "field_name": "SAMLRequest",
            "relay_state": values.get("relay_state", "") or f"relay-{uuid.uuid4().hex[:8]}",
            "xml": sample_authn_request_xml(
                issuer=issuer or "https://sp.example.com/metadata",
                destination=destination or "https://idp.example.com/sso",
                acs_url=acs_url or "https://sp.example.com/saml/acs",
            ),
        }
    if kind == "saml_response":
        return {
            "kind": kind,
            "field_name": "SAMLResponse",
            "relay_state": values.get("relay_state", "") or f"relay-{uuid.uuid4().hex[:8]}",
            "xml": sample_saml_response_xml(
                issuer=issuer or "https://idp.example.com/metadata",
                destination=destination or acs_url or "https://sp.example.com/saml/acs",
                audience=audience or "https://sp.example.com/metadata",
                name_id=name_id or "user@example.com",
                in_response_to=in_response_to or "_example-authn-request",
            ),
        }
    raise ValueError("Example kind must be authn_request or saml_response.")


def html_response(body: str, status: int = 200) -> Response:
    response = make_response(body, status)
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    return response


def absolute_request_url(path: str) -> str:
    return f"{request.host_url.rstrip('/')}{path}"


def render_saml_instance_page() -> Response:
    sso_url = absolute_request_url(CONFIG.saml_instance_sso_path)
    acs_url = absolute_request_url(CONFIG.saml_instance_acs_path)
    request_target = CONFIG.request_forward_url or "(not set)"
    response_target = CONFIG.response_forward_url or "(not set)"
    request_target_class = "" if CONFIG.request_forward_url else " missing"
    response_target_class = "" if CONFIG.response_forward_url else " missing"
    sample_request = html.escape("SAMLRequest=demo-request&RelayState=relay-from-instance")
    sample_response = html.escape("SAMLResponse=demo-response&RelayState=relay-from-instance")

    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SAML Instance Integration</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f7f8fa;
      --text: #17202a;
      --muted: #566573;
      --line: #cfd7df;
      --surface: #ffffff;
      --accent: #2463eb;
      --accent-strong: #1749ad;
      --warn-bg: #fff8e6;
      --warn-line: #d18b00;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Arial, Helvetica, sans-serif;
      font-size: 14px;
      line-height: 1.45;
    }}
    header {{
      border-bottom: 1px solid var(--line);
      background: var(--surface);
    }}
    .wrap {{
      width: min(1120px, calc(100% - 32px));
      margin: 0 auto;
    }}
    .topbar {{
      min-height: 64px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }}
    h1 {{
      margin: 0;
      font-size: 22px;
      letter-spacing: 0;
    }}
    h2 {{
      margin: 0 0 14px;
      font-size: 16px;
      letter-spacing: 0;
    }}
    main {{
      padding: 24px 0 40px;
    }}
    .layout {{
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 18px;
    }}
    .panel {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
    }}
    label {{
      display: block;
      margin: 0 0 6px;
      color: var(--muted);
      font-weight: 700;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
    }}
    input, textarea {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--text);
      font: inherit;
      min-height: 40px;
      padding: 10px 11px;
    }}
    input[readonly] {{
      background: #fbfcfd;
    }}
    textarea {{
      min-height: 96px;
      resize: vertical;
      font-family: Consolas, "Courier New", monospace;
    }}
    .target {{
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 12px;
      overflow-wrap: anywhere;
      background: #fbfcfd;
      min-height: 46px;
    }}
    .target.missing {{
      background: var(--warn-bg);
      border-color: var(--warn-line);
    }}
    .actions {{
      margin-top: 12px;
      display: flex;
      justify-content: flex-end;
      gap: 10px;
    }}
    button, .button-link {{
      border: 1px solid var(--accent);
      border-radius: 6px;
      background: var(--accent);
      color: #fff;
      min-height: 40px;
      padding: 9px 14px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }}
    button:hover, .button-link:hover {{ background: var(--accent-strong); }}
    .ghost {{
      background: #fff;
      color: var(--accent);
    }}
    .ghost:hover {{
      background: #eef4ff;
      color: var(--accent-strong);
    }}
    .stack {{
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 12px;
    }}
    @media (max-width: 760px) {{
      .wrap {{ width: min(100% - 20px, 1120px); }}
      .topbar {{ align-items: flex-start; flex-direction: column; padding: 14px 0; }}
      .grid {{ grid-template-columns: 1fr; }}
      .actions {{ justify-content: stretch; flex-direction: column; }}
      button, .button-link {{ width: 100%; }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="wrap topbar">
      <h1>SAML Instance Integration</h1>
      <a class="button-link ghost" href="/ui/saml-request">Sender</a>
    </div>
  </header>
  <main class="wrap">
    <div class="layout">
      <section class="panel">
        <h2>URLs To Put In The SAML Instance UI</h2>
        <div class="grid">
          <div class="stack">
            <div>
              <label for="sso_url">IdP SSO / Login URL</label>
              <input id="sso_url" readonly value="{html.escape(sso_url)}" />
            </div>
            <div>
              <label>Forwards To</label>
              <div class="target{request_target_class}">{html.escape(request_target)}</div>
            </div>
          </div>
          <div class="stack">
            <div>
              <label for="acs_url">SP ACS / Callback URL</label>
              <input id="acs_url" readonly value="{html.escape(acs_url)}" />
            </div>
            <div>
              <label>Forwards To</label>
              <div class="target{response_target_class}">{html.escape(response_target)}</div>
            </div>
          </div>
        </div>
      </section>
      <section class="panel">
        <h2>Browser Proof Forms</h2>
        <div class="grid">
          <form method="post" action="{html.escape(CONFIG.saml_instance_sso_path)}">
            <label for="sample_request">AuthnRequest Form Body</label>
            <textarea id="sample_request" name="SAMLRequest">demo-request</textarea>
            <input type="hidden" name="RelayState" value="relay-from-instance" />
            <div class="actions"><button type="submit">Send To SSO URL</button></div>
          </form>
          <form method="post" action="{html.escape(CONFIG.saml_instance_acs_path)}">
            <label for="sample_response">SAMLResponse Form Body</label>
            <textarea id="sample_response" name="SAMLResponse">demo-response</textarea>
            <input type="hidden" name="RelayState" value="relay-from-instance" />
            <div class="actions"><button type="submit">Send To ACS URL</button></div>
          </form>
        </div>
      </section>
      <section class="panel">
        <h2>Equivalent Curl Payloads</h2>
        <div class="grid">
          <div>
            <label>Request Branch</label>
            <textarea readonly>curl -X POST "{html.escape(sso_url)}" -H "Content-Type: application/x-www-form-urlencoded" -d "{sample_request}"</textarea>
          </div>
          <div>
            <label>Response Branch</label>
            <textarea readonly>curl -X POST "{html.escape(acs_url)}" -H "Content-Type: application/x-www-form-urlencoded" -d "{sample_response}"</textarea>
          </div>
        </div>
      </section>
    </div>
  </main>
</body>
</html>"""
    return html_response(page)


def html_options_for_saml_targets(selected_choice: str) -> str:
    selected_choice = selected_choice or SAML_INSTANCE_SSO_TARGET_CHOICE
    options = [
        (
            f'<option value="{SAML_INSTANCE_SSO_TARGET_CHOICE}" '
            f'data-url="{html.escape(absolute_request_url(CONFIG.saml_instance_sso_path))}"'
            f'{" selected" if selected_choice == SAML_INSTANCE_SSO_TARGET_CHOICE else ""}>'
            f'Proxy SSO URL - {html.escape(absolute_request_url(CONFIG.saml_instance_sso_path))}</option>'
        ),
        (
            f'<option value="{SAML_INSTANCE_ACS_TARGET_CHOICE}" '
            f'data-url="{html.escape(absolute_request_url(CONFIG.saml_instance_acs_path))}"'
            f'{" selected" if selected_choice == SAML_INSTANCE_ACS_TARGET_CHOICE else ""}>'
            f'Proxy ACS URL - {html.escape(absolute_request_url(CONFIG.saml_instance_acs_path))}</option>'
        ),
    ]
    for idx, target in enumerate(CONFIG.saml_request_targets):
        value = f"preset:{idx}"
        selected = " selected" if selected_choice == value else ""
        label = f"{target['name']} - {target['url']}"
        options.append(
            f'<option value="{html.escape(value)}" data-url="{html.escape(target["url"])}"{selected}>'
            f"{html.escape(label)}</option>"
        )
    custom_selected = " selected" if selected_choice == SAML_CUSTOM_TARGET_CHOICE else ""
    options.append(f'<option value="{SAML_CUSTOM_TARGET_CHOICE}"{custom_selected}>Custom URL</option>')
    return "\n".join(options)


def render_hidden_inputs(fields: Dict[str, str]) -> str:
    return "\n".join(
        f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}" />'
        for k, v in fields.items()
    )


def render_saml_sender_page(error: str = "", values: Optional[Dict[str, str]] = None, result: Optional[Dict] = None) -> Response:
    values = values or {}
    selected_choice = values.get("target_choice", SAML_INSTANCE_SSO_TARGET_CHOICE)
    binding = values.get("binding", "browser_post")
    input_format = values.get("input_format", "raw_xml")
    payload_field_name = values.get("payload_field_name", "SAMLRequest")
    if payload_field_name not in SAML_PAYLOAD_FIELD_NAMES:
        payload_field_name = "SAMLRequest"
    custom_target_url = values.get("custom_target_url", "")
    relay_state = values.get("relay_state", "")
    extra_fields_json = values.get("extra_fields_json", "{}")
    saml_request_value = values.get("saml_request", "")

    error_html = f'<div class="notice error">{html.escape(error)}</div>' if error else ""
    result_html = ""
    if result:
        headers = "\n".join(format_headers(result.get("headers", [])))
        result_html = f"""
        <section class="panel result">
          <h2>Server POST Result</h2>
          <div class="result-grid">
            <div><span>Status</span><strong>{html.escape(str(result.get("status_code", "")))}</strong></div>
            <div><span>Target</span><strong>{html.escape(result.get("target_url", ""))}</strong></div>
            <div><span>Log</span><strong>{html.escape(result.get("log_file", ""))}</strong></div>
          </div>
          <label>Response Headers</label>
          <pre>{html.escape(headers)}</pre>
          <label>Response Body Preview</label>
          <pre>{html.escape(result.get("body_preview", ""))}</pre>
        </section>
        """

    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SAML Request/Response Sender</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f7f8fa;
      --text: #17202a;
      --muted: #566573;
      --line: #cfd7df;
      --surface: #ffffff;
      --accent: #2463eb;
      --accent-strong: #1749ad;
      --error-bg: #fff1f0;
      --error-line: #d93025;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Arial, Helvetica, sans-serif;
      font-size: 14px;
      line-height: 1.45;
    }}
    header {{
      border-bottom: 1px solid var(--line);
      background: var(--surface);
    }}
    .wrap {{
      width: min(1120px, calc(100% - 32px));
      margin: 0 auto;
    }}
    .topbar {{
      min-height: 64px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }}
    .topbar-links {{
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }}
    h1 {{
      margin: 0;
      font-size: 22px;
      font-weight: 700;
      letter-spacing: 0;
    }}
    h2 {{
      margin: 0 0 16px;
      font-size: 16px;
      letter-spacing: 0;
    }}
    main {{
      padding: 24px 0 40px;
    }}
    .layout {{
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 20px;
    }}
    .panel {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
    }}
    .full {{ grid-column: 1 / -1; }}
    label {{
      display: block;
      margin: 0 0 6px;
      color: var(--muted);
      font-weight: 700;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
    }}
    input, select, textarea {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--text);
      font: inherit;
      padding: 10px 11px;
      min-height: 40px;
    }}
    textarea {{
      min-height: 260px;
      resize: vertical;
      font-family: Consolas, "Courier New", monospace;
      line-height: 1.4;
    }}
    .extra-fields {{ min-height: 96px; }}
    .actions {{
      display: flex;
      justify-content: flex-end;
      gap: 10px;
      margin-top: 16px;
    }}
    button, .button-link {{
      border: 1px solid var(--accent);
      border-radius: 6px;
      background: var(--accent);
      color: #fff;
      min-height: 40px;
      padding: 9px 14px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }}
    button:hover, .button-link:hover {{ background: var(--accent-strong); }}
    .ghost {{
      background: #fff;
      color: var(--accent);
    }}
    .ghost:hover {{
      background: #eef4ff;
      color: var(--accent-strong);
    }}
    .notice {{
      border-radius: 6px;
      padding: 10px 12px;
      margin-bottom: 16px;
      font-weight: 700;
    }}
    .error {{
      background: var(--error-bg);
      border: 1px solid var(--error-line);
      color: #9f1d16;
    }}
    .result-grid {{
      display: grid;
      grid-template-columns: 120px minmax(0, 1fr) minmax(0, 1fr);
      gap: 10px;
      margin-bottom: 16px;
    }}
    .result-grid div {{
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 10px;
      min-width: 0;
    }}
    .result-grid span {{
      display: block;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .result-grid strong {{
      display: block;
      overflow-wrap: anywhere;
      margin-top: 4px;
    }}
    pre {{
      margin: 0 0 14px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fbfcfd;
      padding: 12px;
      overflow: auto;
      max-height: 320px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      font-family: Consolas, "Courier New", monospace;
      font-size: 13px;
    }}
    @media (max-width: 760px) {{
      .wrap {{ width: min(100% - 20px, 1120px); }}
      .topbar {{ align-items: flex-start; flex-direction: column; padding: 14px 0; }}
      .grid, .result-grid {{ grid-template-columns: 1fr; }}
      .actions {{ justify-content: stretch; flex-direction: column; }}
      button, .button-link {{ width: 100%; }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="wrap topbar">
      <h1>SAML Request/Response Sender</h1>
      <div class="topbar-links">
        <a class="button-link ghost" href="/ui/saml-instance">Instance URLs</a>
        <a class="button-link ghost" href="/healthz">Health</a>
      </div>
    </div>
  </header>
  <main class="wrap">
    <div class="layout">
      <section class="panel">
        <h2>Example Generator</h2>
        <div class="grid">
          <div>
            <label for="example_kind">Example</label>
            <select id="example_kind">
              <option value="authn_request">AuthnRequest</option>
              <option value="saml_response">SAMLResponse</option>
            </select>
          </div>
          <div>
            <label for="example_issuer">Issuer</label>
            <input id="example_issuer" value="https://sp.example.com/metadata" />
          </div>
          <div>
            <label for="example_destination">Destination</label>
            <input id="example_destination" value="https://idp.example.com/sso" />
          </div>
          <div>
            <label for="example_acs_url">ACS URL</label>
            <input id="example_acs_url" value="https://sp.example.com/saml/acs" />
          </div>
          <div>
            <label for="example_audience">Audience</label>
            <input id="example_audience" value="https://sp.example.com/metadata" />
          </div>
          <div>
            <label for="example_name_id">NameID</label>
            <input id="example_name_id" value="user@example.com" />
          </div>
          <div>
            <label for="example_in_response_to">InResponseTo</label>
            <input id="example_in_response_to" value="_example-authn-request" />
          </div>
        </div>
        <div class="actions">
          <button type="button" id="generate_example">Load Example</button>
        </div>
      </section>
      <section class="panel">
        <h2>Request</h2>
        {error_html}
        <form method="post" action="/saml/send">
          <div class="grid">
            <div>
              <label for="target_choice">Destination</label>
              <select id="target_choice" name="target_choice">
                {html_options_for_saml_targets(selected_choice)}
              </select>
            </div>
            <div>
              <label for="custom_target_url">Custom URL</label>
              <input id="custom_target_url" name="custom_target_url" value="{html.escape(custom_target_url)}" />
            </div>
            <div>
              <label for="binding">Binding</label>
              <select id="binding" name="binding">
                <option value="browser_post"{" selected" if binding == "browser_post" else ""}>Browser POST</option>
                <option value="browser_redirect"{" selected" if binding == "browser_redirect" else ""}>Browser Redirect</option>
                <option value="server_post"{" selected" if binding == "server_post" else ""}>Server POST</option>
              </select>
            </div>
            <div>
              <label for="payload_field_name">Payload Field</label>
              <select id="payload_field_name" name="payload_field_name">
                <option value="SAMLRequest"{" selected" if payload_field_name == "SAMLRequest" else ""}>SAMLRequest</option>
                <option value="SAMLResponse"{" selected" if payload_field_name == "SAMLResponse" else ""}>SAMLResponse</option>
              </select>
            </div>
            <div>
              <label for="input_format">Payload Format</label>
              <select id="input_format" name="input_format">
                <option value="raw_xml"{" selected" if input_format == "raw_xml" else ""}>Raw XML</option>
                <option value="encoded"{" selected" if input_format == "encoded" else ""}>Already Encoded</option>
              </select>
            </div>
            <div>
              <label for="relay_state">RelayState</label>
              <input id="relay_state" name="relay_state" value="{html.escape(relay_state)}" />
            </div>
            <div>
              <label for="extra_fields_json">Extra Fields JSON</label>
              <textarea class="extra-fields" id="extra_fields_json" name="extra_fields_json">{html.escape(extra_fields_json)}</textarea>
            </div>
            <div class="full">
              <label for="saml_request">SAML Payload</label>
              <textarea id="saml_request" name="saml_request">{html.escape(saml_request_value)}</textarea>
            </div>
          </div>
          <div class="actions">
            <button type="submit">Send</button>
          </div>
        </form>
      </section>
      {result_html}
    </div>
  </main>
  <script>
    const targetChoice = document.getElementById('target_choice');
    const customTarget = document.getElementById('custom_target_url');
    const payloadField = document.getElementById('payload_field_name');
    const relayState = document.getElementById('relay_state');
    const samlPayload = document.getElementById('saml_request');
    const inputFormat = document.getElementById('input_format');
    const exampleKind = document.getElementById('example_kind');
    const exampleIssuer = document.getElementById('example_issuer');
    const exampleDestination = document.getElementById('example_destination');
    const exampleAcsUrl = document.getElementById('example_acs_url');
    const exampleAudience = document.getElementById('example_audience');
    const exampleNameId = document.getElementById('example_name_id');
    const exampleInResponseTo = document.getElementById('example_in_response_to');
    const generateExample = document.getElementById('generate_example');
    function syncCustomTarget() {{
      const custom = targetChoice.value === '{SAML_CUSTOM_TARGET_CHOICE}';
      customTarget.disabled = !custom;
      customTarget.required = custom;
      if (!custom && targetChoice.selectedOptions.length && targetChoice.selectedOptions[0].dataset.url) {{
        exampleDestination.value = targetChoice.selectedOptions[0].dataset.url;
      }}
    }}
    function syncExampleDefaults() {{
      if (exampleKind.value === 'authn_request') {{
        exampleIssuer.value = exampleIssuer.value || 'https://sp.example.com/metadata';
        exampleDestination.value = targetChoice.selectedOptions.length && targetChoice.selectedOptions[0].dataset.url
          ? targetChoice.selectedOptions[0].dataset.url
          : (exampleDestination.value || 'https://idp.example.com/sso');
      }} else {{
        exampleIssuer.value = exampleIssuer.value || 'https://idp.example.com/metadata';
        exampleDestination.value = exampleAcsUrl.value || exampleDestination.value || 'https://sp.example.com/saml/acs';
      }}
    }}
    async function loadExample() {{
      syncExampleDefaults();
      const body = new URLSearchParams();
      body.set('kind', exampleKind.value);
      body.set('issuer', exampleIssuer.value);
      body.set('destination', exampleDestination.value);
      body.set('acs_url', exampleAcsUrl.value);
      body.set('audience', exampleAudience.value);
      body.set('name_id', exampleNameId.value);
      body.set('in_response_to', exampleInResponseTo.value);
      body.set('relay_state', relayState.value);
      const response = await fetch('/saml/example', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
        body
      }});
      const data = await response.json();
      if (!response.ok) {{
        throw new Error(data.error || 'Example generation failed.');
      }}
      payloadField.value = data.field_name;
      targetChoice.value = data.field_name === 'SAMLResponse' ? '{SAML_INSTANCE_ACS_TARGET_CHOICE}' : '{SAML_INSTANCE_SSO_TARGET_CHOICE}';
      samlPayload.value = data.xml;
      inputFormat.value = 'raw_xml';
      if (!relayState.value && data.relay_state) {{
        relayState.value = data.relay_state;
      }}
    }}
    targetChoice.addEventListener('change', syncCustomTarget);
    exampleKind.addEventListener('change', syncExampleDefaults);
    generateExample.addEventListener('click', () => {{
      loadExample().catch((error) => alert(error.message));
    }});
    syncCustomTarget();
    syncExampleDefaults();
  </script>
</body>
</html>"""
    return html_response(page)


def render_saml_browser_post_page(target_url: str, fields: Dict[str, str], request_id: str) -> Response:
    hidden_inputs = render_hidden_inputs(fields)
    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>SAML POST</title>
</head>
<body>
  <form id="saml_request_form" method="post" action="{html.escape(target_url)}">
    {hidden_inputs}
    <button type="submit">Continue</button>
  </form>
  <script>document.getElementById('saml_request_form').submit();</script>
  <!-- request_id={html.escape(request_id)} -->
</body>
</html>"""
    return html_response(page)


def render_unified_ui_page(
    active_tab: str = "instance",
    error: str = "",
    values: Optional[Dict[str, str]] = None,
    result: Optional[Dict] = None,
) -> Response:
    values = values or {}
    active_tab = active_tab if active_tab in {"instance", "sender", "status"} else "instance"
    sso_url = absolute_request_url(CONFIG.saml_instance_sso_path)
    acs_url = absolute_request_url(CONFIG.saml_instance_acs_path)
    request_target = CONFIG.request_forward_url or "(not set)"
    response_target = CONFIG.response_forward_url or "(not set)"
    request_target_class = "" if CONFIG.request_forward_url else " missing"
    response_target_class = "" if CONFIG.response_forward_url else " missing"
    selected_choice = values.get("target_choice", SAML_INSTANCE_SSO_TARGET_CHOICE)
    binding = values.get("binding", "browser_post")
    input_format = values.get("input_format", "raw_xml")
    payload_field_name = values.get("payload_field_name", "SAMLRequest")
    if payload_field_name not in SAML_PAYLOAD_FIELD_NAMES:
        payload_field_name = "SAMLRequest"
    custom_target_url = values.get("custom_target_url", "")
    relay_state = values.get("relay_state", "")
    extra_fields_json = values.get("extra_fields_json", "{}")
    saml_request_value = values.get("saml_request", "")
    sample_request = html.escape("SAMLRequest=demo-request&RelayState=relay-from-instance")
    sample_response = html.escape("SAMLResponse=demo-response&RelayState=relay-from-instance")
    error_html = f'<div class="notice error">{html.escape(error)}</div>' if error else ""

    result_html = ""
    if result:
        headers = "\n".join(format_headers(result.get("headers", [])))
        result_html = f"""
        <section class="panel result">
          <h2>Server POST Result</h2>
          <div class="result-grid">
            <div><span>Status</span><strong>{html.escape(str(result.get("status_code", "")))}</strong></div>
            <div><span>Target</span><strong>{html.escape(result.get("target_url", ""))}</strong></div>
            <div><span>Log</span><strong>{html.escape(result.get("log_file", ""))}</strong></div>
          </div>
          <label>Response Headers</label>
          <pre>{html.escape(headers)}</pre>
          <label>Response Body Preview</label>
          <pre>{html.escape(result.get("body_preview", ""))}</pre>
        </section>
        """

    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Request Capture Proxy UI</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f7f8fa;
      --text: #17202a;
      --muted: #566573;
      --line: #cfd7df;
      --surface: #ffffff;
      --accent: #2463eb;
      --accent-strong: #1749ad;
      --warn-bg: #fff8e6;
      --warn-line: #d18b00;
      --error-bg: #fff1f0;
      --error-line: #d93025;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Arial, Helvetica, sans-serif;
      font-size: 14px;
      line-height: 1.45;
    }}
    header {{
      background: var(--surface);
      border-bottom: 1px solid var(--line);
      position: sticky;
      top: 0;
      z-index: 2;
    }}
    .wrap {{
      width: min(1180px, calc(100% - 32px));
      margin: 0 auto;
    }}
    .topbar {{
      min-height: 64px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }}
    h1 {{
      margin: 0;
      font-size: 22px;
      letter-spacing: 0;
    }}
    h2 {{
      margin: 0 0 14px;
      font-size: 16px;
      letter-spacing: 0;
    }}
    main {{
      padding: 20px 0 40px;
    }}
    .tabs {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }}
    .tab-button {{
      border: 1px solid var(--line);
      background: #fff;
      color: var(--text);
      border-radius: 6px;
      min-height: 38px;
      padding: 8px 12px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
    }}
    .tab-button.active {{
      border-color: var(--accent);
      background: var(--accent);
      color: #fff;
    }}
    .tab-panel {{ display: none; }}
    .tab-panel.active {{ display: block; }}
    .layout {{
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 18px;
    }}
    .panel {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
    }}
    .full {{ grid-column: 1 / -1; }}
    .stack {{
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 12px;
    }}
    label {{
      display: block;
      margin: 0 0 6px;
      color: var(--muted);
      font-weight: 700;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
    }}
    input, select, textarea {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--text);
      font: inherit;
      padding: 10px 11px;
      min-height: 40px;
    }}
    input[readonly], textarea[readonly] {{ background: #fbfcfd; }}
    textarea {{
      min-height: 120px;
      resize: vertical;
      font-family: Consolas, "Courier New", monospace;
      line-height: 1.4;
    }}
    .large-textarea {{ min-height: 260px; }}
    .extra-fields {{ min-height: 96px; }}
    .target {{
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 12px;
      overflow-wrap: anywhere;
      background: #fbfcfd;
      min-height: 46px;
    }}
    .target.missing {{
      background: var(--warn-bg);
      border-color: var(--warn-line);
    }}
    .actions {{
      display: flex;
      justify-content: flex-end;
      gap: 10px;
      margin-top: 14px;
    }}
    button, .button-link {{
      border: 1px solid var(--accent);
      border-radius: 6px;
      background: var(--accent);
      color: #fff;
      min-height: 40px;
      padding: 9px 14px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }}
    button:hover, .button-link:hover {{ background: var(--accent-strong); }}
    .ghost {{
      background: #fff;
      color: var(--accent);
    }}
    .ghost:hover {{
      background: #eef4ff;
      color: var(--accent-strong);
    }}
    .notice {{
      border-radius: 6px;
      padding: 10px 12px;
      margin-bottom: 16px;
      font-weight: 700;
    }}
    .error {{
      background: var(--error-bg);
      border: 1px solid var(--error-line);
      color: #9f1d16;
    }}
    .result-grid {{
      display: grid;
      grid-template-columns: 120px minmax(0, 1fr) minmax(0, 1fr);
      gap: 10px;
      margin-bottom: 16px;
    }}
    .result-grid div {{
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 10px;
      min-width: 0;
    }}
    .result-grid span {{
      display: block;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .result-grid strong {{
      display: block;
      overflow-wrap: anywhere;
      margin-top: 4px;
    }}
    pre {{
      margin: 0 0 14px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fbfcfd;
      padding: 12px;
      overflow: auto;
      max-height: 320px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      font-family: Consolas, "Courier New", monospace;
      font-size: 13px;
    }}
    @media (max-width: 760px) {{
      .wrap {{ width: min(100% - 20px, 1180px); }}
      .topbar {{ align-items: flex-start; flex-direction: column; padding: 14px 0; }}
      .grid, .result-grid {{ grid-template-columns: 1fr; }}
      .actions {{ justify-content: stretch; flex-direction: column; }}
      button, .button-link, .tab-button {{ width: 100%; }}
      .tabs {{ width: 100%; }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="wrap topbar">
      <h1>Request Capture Proxy</h1>
      <nav class="tabs" aria-label="UI modes">
        <button type="button" class="tab-button" data-tab="instance">Instance Setup</button>
        <button type="button" class="tab-button" data-tab="sender">Send / Generate</button>
        <button type="button" class="tab-button" data-tab="status">Status</button>
      </nav>
    </div>
  </header>
  <main class="wrap">
    <section id="tab-instance" class="tab-panel">
      <div class="layout">
        <section class="panel">
          <h2>SAML Instance Integration</h2>
          <div class="grid">
            <div class="stack">
              <div>
                <label for="sso_url">IdP SSO / Login URL</label>
                <input id="sso_url" readonly value="{html.escape(sso_url)}" />
              </div>
              <div>
                <label>Forwards To</label>
                <div class="target{request_target_class}">{html.escape(request_target)}</div>
              </div>
            </div>
            <div class="stack">
              <div>
                <label for="acs_url">SP ACS / Callback URL</label>
                <input id="acs_url" readonly value="{html.escape(acs_url)}" />
              </div>
              <div>
                <label>Forwards To</label>
                <div class="target{response_target_class}">{html.escape(response_target)}</div>
              </div>
            </div>
          </div>
        </section>
        <section class="panel">
          <h2>Browser Proof Forms</h2>
          <div class="grid">
            <form method="post" action="{html.escape(CONFIG.saml_instance_sso_path)}">
              <label for="sample_request">AuthnRequest Form Body</label>
              <textarea id="sample_request" name="SAMLRequest">demo-request</textarea>
              <input type="hidden" name="RelayState" value="relay-from-instance" />
              <div class="actions"><button type="submit">Send To SSO URL</button></div>
            </form>
            <form method="post" action="{html.escape(CONFIG.saml_instance_acs_path)}">
              <label for="sample_response">SAMLResponse Form Body</label>
              <textarea id="sample_response" name="SAMLResponse">demo-response</textarea>
              <input type="hidden" name="RelayState" value="relay-from-instance" />
              <div class="actions"><button type="submit">Send To ACS URL</button></div>
            </form>
          </div>
        </section>
      </div>
    </section>

    <section id="tab-sender" class="tab-panel">
      <div class="layout">
        <section class="panel">
          <h2>SAML Request/Response Sender</h2>
          <h2>Example Generator</h2>
          <div class="grid">
            <div>
              <label for="example_kind">Example</label>
              <select id="example_kind">
                <option value="authn_request">AuthnRequest</option>
                <option value="saml_response">SAMLResponse</option>
              </select>
            </div>
            <div>
              <label for="example_issuer">Issuer</label>
              <input id="example_issuer" value="https://sp.example.com/metadata" />
            </div>
            <div>
              <label for="example_destination">Destination</label>
              <input id="example_destination" value="https://idp.example.com/sso" />
            </div>
            <div>
              <label for="example_acs_url">ACS URL</label>
              <input id="example_acs_url" value="https://sp.example.com/saml/acs" />
            </div>
            <div>
              <label for="example_audience">Audience</label>
              <input id="example_audience" value="https://sp.example.com/metadata" />
            </div>
            <div>
              <label for="example_name_id">NameID</label>
              <input id="example_name_id" value="user@example.com" />
            </div>
            <div>
              <label for="example_in_response_to">InResponseTo</label>
              <input id="example_in_response_to" value="_example-authn-request" />
            </div>
          </div>
          <div class="actions"><button type="button" id="generate_example">Load Example</button></div>
        </section>
        <section class="panel">
          <h2>Send</h2>
          {error_html}
          <form method="post" action="/saml/send">
            <div class="grid">
              <div>
                <label for="target_choice">Destination</label>
                <select id="target_choice" name="target_choice">
                  {html_options_for_saml_targets(selected_choice)}
                </select>
              </div>
              <div>
                <label for="custom_target_url">Custom URL</label>
                <input id="custom_target_url" name="custom_target_url" value="{html.escape(custom_target_url)}" />
              </div>
              <div>
                <label for="binding">Binding</label>
                <select id="binding" name="binding">
                  <option value="browser_post"{" selected" if binding == "browser_post" else ""}>Browser POST</option>
                  <option value="browser_redirect"{" selected" if binding == "browser_redirect" else ""}>Browser Redirect</option>
                  <option value="server_post"{" selected" if binding == "server_post" else ""}>Server POST</option>
                </select>
              </div>
              <div>
                <label for="payload_field_name">Payload Field</label>
                <select id="payload_field_name" name="payload_field_name">
                  <option value="SAMLRequest"{" selected" if payload_field_name == "SAMLRequest" else ""}>SAMLRequest</option>
                  <option value="SAMLResponse"{" selected" if payload_field_name == "SAMLResponse" else ""}>SAMLResponse</option>
                </select>
              </div>
              <div>
                <label for="input_format">Payload Format</label>
                <select id="input_format" name="input_format">
                  <option value="raw_xml"{" selected" if input_format == "raw_xml" else ""}>Raw XML</option>
                  <option value="encoded"{" selected" if input_format == "encoded" else ""}>Already Encoded</option>
                </select>
              </div>
              <div>
                <label for="relay_state">RelayState</label>
                <input id="relay_state" name="relay_state" value="{html.escape(relay_state)}" />
              </div>
              <div>
                <label for="extra_fields_json">Extra Fields JSON</label>
                <textarea class="extra-fields" id="extra_fields_json" name="extra_fields_json">{html.escape(extra_fields_json)}</textarea>
              </div>
              <div class="full">
                <label for="saml_request">SAML Payload</label>
                <textarea class="large-textarea" id="saml_request" name="saml_request">{html.escape(saml_request_value)}</textarea>
              </div>
            </div>
            <div class="actions"><button type="submit">Send</button></div>
          </form>
        </section>
        {result_html}
      </div>
    </section>

    <section id="tab-status" class="tab-panel">
      <div class="layout">
        <section class="panel">
          <h2>Status</h2>
          <div class="grid">
            <div>
              <label>Health Endpoint</label>
              <textarea readonly>curl {html.escape(absolute_request_url("/healthz"))}</textarea>
            </div>
            <div>
              <label>Latest Capture Files</label>
              <textarea readonly>Get-ChildItem .\\logs | Sort-Object LastWriteTime -Descending | Select-Object -First 5</textarea>
            </div>
            <div>
              <label>Request Branch Proof</label>
              <textarea readonly>curl -X POST "{html.escape(sso_url)}" -H "Content-Type: application/x-www-form-urlencoded" -d "{sample_request}"</textarea>
            </div>
            <div>
              <label>Response Branch Proof</label>
              <textarea readonly>curl -X POST "{html.escape(acs_url)}" -H "Content-Type: application/x-www-form-urlencoded" -d "{sample_response}"</textarea>
            </div>
          </div>
          <div class="actions"><a class="button-link" href="/healthz">Open Health</a></div>
        </section>
      </div>
    </section>
  </main>
  <script>
    const initialTab = '{active_tab}';
    const tabs = Array.from(document.querySelectorAll('.tab-button'));
    const panels = Array.from(document.querySelectorAll('.tab-panel'));
    function showTab(name) {{
      tabs.forEach((tab) => tab.classList.toggle('active', tab.dataset.tab === name));
      panels.forEach((panel) => panel.classList.toggle('active', panel.id === `tab-${{name}}`));
      if (location.hash !== `#${{name}}`) {{
        history.replaceState(null, '', `#${{name}}`);
      }}
    }}
    tabs.forEach((tab) => tab.addEventListener('click', () => showTab(tab.dataset.tab)));
    showTab(location.hash ? location.hash.slice(1) : initialTab);

    const targetChoice = document.getElementById('target_choice');
    const customTarget = document.getElementById('custom_target_url');
    const payloadField = document.getElementById('payload_field_name');
    const relayState = document.getElementById('relay_state');
    const samlPayload = document.getElementById('saml_request');
    const inputFormat = document.getElementById('input_format');
    const exampleKind = document.getElementById('example_kind');
    const exampleIssuer = document.getElementById('example_issuer');
    const exampleDestination = document.getElementById('example_destination');
    const exampleAcsUrl = document.getElementById('example_acs_url');
    const exampleAudience = document.getElementById('example_audience');
    const exampleNameId = document.getElementById('example_name_id');
    const exampleInResponseTo = document.getElementById('example_in_response_to');
    const generateExample = document.getElementById('generate_example');
    function syncCustomTarget() {{
      const custom = targetChoice.value === '{SAML_CUSTOM_TARGET_CHOICE}';
      customTarget.disabled = !custom;
      customTarget.required = custom;
      if (!custom && targetChoice.selectedOptions.length && targetChoice.selectedOptions[0].dataset.url) {{
        exampleDestination.value = targetChoice.selectedOptions[0].dataset.url;
      }}
    }}
    function syncExampleDefaults() {{
      if (exampleKind.value === 'authn_request') {{
        exampleIssuer.value = exampleIssuer.value || 'https://sp.example.com/metadata';
        exampleDestination.value = targetChoice.selectedOptions.length && targetChoice.selectedOptions[0].dataset.url
          ? targetChoice.selectedOptions[0].dataset.url
          : (exampleDestination.value || 'https://idp.example.com/sso');
      }} else {{
        exampleIssuer.value = exampleIssuer.value || 'https://idp.example.com/metadata';
        exampleDestination.value = exampleAcsUrl.value || exampleDestination.value || 'https://sp.example.com/saml/acs';
      }}
    }}
    async function loadExample() {{
      syncExampleDefaults();
      const body = new URLSearchParams();
      body.set('kind', exampleKind.value);
      body.set('issuer', exampleIssuer.value);
      body.set('destination', exampleDestination.value);
      body.set('acs_url', exampleAcsUrl.value);
      body.set('audience', exampleAudience.value);
      body.set('name_id', exampleNameId.value);
      body.set('in_response_to', exampleInResponseTo.value);
      body.set('relay_state', relayState.value);
      const response = await fetch('/saml/example', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
        body
      }});
      const data = await response.json();
      if (!response.ok) {{
        throw new Error(data.error || 'Example generation failed.');
      }}
      payloadField.value = data.field_name;
      targetChoice.value = data.field_name === 'SAMLResponse' ? '{SAML_INSTANCE_ACS_TARGET_CHOICE}' : '{SAML_INSTANCE_SSO_TARGET_CHOICE}';
      samlPayload.value = data.xml;
      inputFormat.value = 'raw_xml';
      if (!relayState.value && data.relay_state) {{
        relayState.value = data.relay_state;
      }}
      showTab('sender');
    }}
    targetChoice.addEventListener('change', syncCustomTarget);
    exampleKind.addEventListener('change', syncExampleDefaults);
    generateExample.addEventListener('click', () => {{
      loadExample().catch((error) => alert(error.message));
    }});
    syncCustomTarget();
    syncExampleDefaults();
  </script>
</body>
</html>"""
    return html_response(page)


def log_saml_send_source(
    log: RequestFileLog,
    request_id: str,
    target_url: str,
    binding: str,
    input_format: str,
    payload_field_name: str,
    raw_saml_payload: str,
    relay_state: str,
    extra_fields: Dict[str, str],
) -> None:
    log.section(f"SAML SEND SOURCE [{request_id}]")
    log.line(f"Target: {target_url}")
    log.line(f"Binding: {binding}")
    log.line(f"Payload-Field: {payload_field_name}")
    log.line(f"Payload-Input-Format: {input_format}")
    log.line(f"RelayState: {relay_state or '(empty)'}")
    log.line("Extra Fields:")
    if extra_fields:
        for key, value in extra_fields.items():
            log.line(f"  {key}: {value}")
    else:
        log.line("  (none)")
    log.line("Original SAML Payload:")
    for line in body_preview("text/plain", raw_saml_payload.encode("utf-8"), CONFIG.max_body_log_bytes).splitlines():
        log.line(f"  {line}")


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
        f"[startup] saml_instance_sso_path={CONFIG.saml_instance_sso_path}",
        f"[startup] saml_instance_acs_path={CONFIG.saml_instance_acs_path}",
        f"[startup] request_forward_url={CONFIG.request_forward_url or '(not set)'}",
        f"[startup] response_forward_url={CONFIG.response_forward_url or '(not set)'}",
        f"[startup] log_dir={CONFIG.log_dir}",
        f"[startup] ui_url=http://{external_host}:{CONFIG.listen_port}/ui",
        f"[startup] saml_request_targets={len(CONFIG.saml_request_targets)}",
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


@APP.get("/ui")
def ui_home():
    return render_unified_ui_page(active_tab="instance")


@APP.get("/ui/saml-instance")
def saml_instance_ui():
    return render_unified_ui_page(active_tab="instance")


@APP.get("/ui/saml-request")
def saml_request_sender_ui():
    return render_unified_ui_page(active_tab="sender")


@APP.post("/saml/example")
def saml_example() -> Response:
    try:
        payload = build_saml_example_payload(
            {
                "kind": request.form.get("kind", "authn_request"),
                "issuer": request.form.get("issuer", ""),
                "destination": request.form.get("destination", ""),
                "acs_url": request.form.get("acs_url", ""),
                "audience": request.form.get("audience", ""),
                "name_id": request.form.get("name_id", ""),
                "in_response_to": request.form.get("in_response_to", ""),
                "relay_state": request.form.get("relay_state", ""),
            }
        )
        return json_response(payload)
    except Exception as exc:
        return json_response({"error": str(exc)}, 400)


@APP.post("/saml/send")
def send_saml_request() -> Response:
    request_id = uuid.uuid4().hex[:12]
    log = RequestFileLog(CONFIG, f"saml_send_{request_id}")
    started_at = datetime.now(timezone.utc).isoformat()
    log.line(f"request_id={request_id}")
    log.line(f"started_at={started_at}")
    log.line("mode=saml_sender")

    form_values = {
        "target_choice": request.form.get("target_choice", ""),
        "custom_target_url": request.form.get("custom_target_url", ""),
        "binding": request.form.get("binding", "browser_post"),
        "input_format": request.form.get("input_format", "raw_xml"),
        "payload_field_name": request.form.get("payload_field_name", "SAMLRequest"),
        "relay_state": request.form.get("relay_state", ""),
        "extra_fields_json": request.form.get("extra_fields_json", "{}"),
        "saml_request": request.form.get("saml_request", ""),
    }

    try:
        target_url = selected_saml_target(form_values["target_choice"], form_values["custom_target_url"])
        binding = form_values["binding"]
        input_format = form_values["input_format"]
        payload_field_name = validate_saml_payload_field_name(form_values["payload_field_name"])
        relay_state = form_values["relay_state"].strip()
        extra_fields = parse_extra_fields(form_values["extra_fields_json"].strip())
        encoded_payload = encode_saml_request_payload(form_values["saml_request"], binding, input_format)
        fields = build_saml_send_fields(payload_field_name, encoded_payload, relay_state, extra_fields)

        log_saml_send_source(
            log=log,
            request_id=request_id,
            target_url=target_url,
            binding=binding,
            input_format=input_format,
            payload_field_name=payload_field_name,
            raw_saml_payload=form_values["saml_request"],
            relay_state=relay_state,
            extra_fields=extra_fields,
        )

        if binding == "browser_redirect":
            redirect_url = append_query_params(target_url, fields)
            log_message_block(
                log=log,
                title=f"SAML SEND REQUEST [{request_id}]",
                method="GET",
                url=redirect_url,
                headers=[],
                body=b"",
            )
            response = make_response("", 302)
            response.headers["Location"] = redirect_url
            return response

        encoded_body = urlencode(fields).encode("utf-8")
        outbound_headers = [("Content-Type", "application/x-www-form-urlencoded")]
        log_message_block(
            log=log,
            title=f"SAML SEND REQUEST [{request_id}]",
            method="POST",
            url=target_url,
            headers=outbound_headers,
            body=encoded_body,
        )

        if binding == "browser_post":
            return render_saml_browser_post_page(target_url, fields, request_id)

        if binding != "server_post":
            raise ValueError("Unsupported SAML sender binding.")

        upstream = HTTP.request(
            method="POST",
            url=target_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=encoded_body,
            timeout=CONFIG.request_timeout_seconds,
            allow_redirects=False,
        )
        upstream_headers = upstream_header_items(upstream)
        log_message_block(
            log=log,
            title=f"SAML SEND RESPONSE [{request_id}]",
            method="POST",
            url=target_url,
            headers=upstream_headers,
            body=upstream.content,
            status=upstream.status_code,
        )
        content_type = first_header_value(upstream_headers, "Content-Type")
        result = {
            "status_code": upstream.status_code,
            "target_url": target_url,
            "headers": upstream_headers,
            "body_preview": body_preview(content_type, upstream.content, CONFIG.max_body_log_bytes),
            "log_file": str(log.file_path),
        }
        return render_unified_ui_page(active_tab="sender", values=form_values, result=result)
    except requests.RequestException as exc:
        log.section(f"ERROR [{request_id}]")
        log.line(str(exc))
        return render_unified_ui_page(active_tab="sender", error=f"Send failed: {exc}", values=form_values), 502
    except Exception as exc:
        log.section(f"ERROR [{request_id}]")
        log.line(traceback.format_exc())
        return render_unified_ui_page(active_tab="sender", error=str(exc), values=form_values), 400
    finally:
        log.line()
        log.line(f"finished_at={datetime.now(timezone.utc).isoformat()}")
        log.close()


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
