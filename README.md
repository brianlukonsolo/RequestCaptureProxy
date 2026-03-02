# 🧭 Request Capture Proxy

Debug and replay utility for SAML/API-gateway traffic with two modes:

- 🔁 `proxy` mode: forward traffic and log full request/response details.
- 🪪 `idp` mode: return a static SAML response immediately (no validation), including auto-POST behavior.

---

## ✨ Highlights

- 📁 One log file per request in `LOG_DIR`
- 🧾 Captures:
  - all headers
  - full body (with truncation guard via `MAX_BODY_LOG_BYTES`)
  - multipart attachment metadata plus content preview
- 🧱 Clear log boundaries:
  - `REQUEST START`
  - `FORWARDED REQUEST`
  - `RESPONSE END`
- 🧭 Two forwarding branches:
  - `REQUEST_FORWARD_URL`
  - `RESPONSE_FORWARD_URL`
- 🪄 IdP emulation that can place SAML response in:
  - HTML form field
  - cookie
  - response header
  - custom body template
- ❤️ Health endpoint: `GET /healthz`

---

## 🏗️ Architecture

Default `docker-compose` stack starts three services:

- 🚪 `request-capture-proxy` on `http://localhost:8080`
- 🧪 `mock-request-upstream` on `http://localhost:18081`
- 🧪 `mock-response-upstream` on `http://localhost:18082`

Default forwarding:

- `REQUEST_FORWARD_URL=http://mock-request-upstream:18081`
- `RESPONSE_FORWARD_URL=http://mock-response-upstream:18082`

---

## 📦 Prerequisites

- 🐳 Docker Desktop (for compose workflow)
- 🐍 Python 3.11+ (for local non-docker runs)

---

## 🚀 Quick Start (Docker Compose)

1. Create runtime config file:

```powershell
Copy-Item .env.example .env
```

2. Start everything:

```bash
docker compose up --build -d
```

3. Follow logs:

```bash
docker compose logs -f
```

4. Stop stack:

```bash
docker compose down
```

---

## 🔊 Startup Logs (Clear Service Identity)

Each container prints explicit startup banners, for example:

- `[startup] service=request-capture-proxy`
- `[startup] service=mock-request-upstream`
- `[startup] service=mock-response-upstream`
- plus bind address, local URL, health URL, and key endpoint examples

This is designed so `docker compose logs -f` is instantly readable.

---

## 🧰 Modes

### 🔁 Proxy Mode

Set:

- `MODE=proxy`
- `REQUEST_FORWARD_URL=<request upstream>`
- `RESPONSE_FORWARD_URL=<response upstream>`

Call paths:

- `http://localhost:8080/forward/request/...` → `REQUEST_FORWARD_URL/...`
- `http://localhost:8080/forward/response/...` → `RESPONSE_FORWARD_URL/...`

Fallback:

- Any non-matching path falls back to request branch (`REQUEST_FORWARD_URL`)

### 🪪 IdP Mode

Set:

- `MODE=idp`
- `IDP_POST_URL=https://sp.example.com/saml/acs`
- `IDP_SAML_RESPONSE=<your static SAMLResponse>`

Behavior:

- Accepts inbound request as-is
- Performs no validation
- Returns configured static response immediately
- Default output is an auto-submit HTML form POST to `IDP_POST_URL`

Optional output placement:

- `IDP_FORM_FIELD_NAME` (default `SAMLResponse`)
- `IDP_SET_COOKIE_NAME`
- `IDP_SET_HEADER_NAME`
- `IDP_BODY_TEMPLATE`

Template placeholders:

- `{{SAML_RESPONSE}}`
- `{{POST_URL}}`
- `{{FORM_FIELD_NAME}}`
- `{{RELAY_STATE}}`
- `{{FORM_FIELDS_JSON}}`

RelayState behavior:

- `IDP_PASSTHROUGH_RELAY_STATE=true` uses inbound `RelayState` if present
- `IDP_RELAY_STATE` acts as fallback/static value

---

## 🧪 Built-in Mock Upstream Endpoints

Available on both mock services (`:18081` and `:18082`):

- `GET /healthz`
- `GET|POST|PUT|PATCH|DELETE /...` (echo request details as JSON)
- `GET /image/png` (binary response)
- `GET /response-headers?Set-Cookie=a%3D1&Set-Cookie=b%3D2` (duplicate-header test)
- `GET /status/<code>` (custom status response)
- `GET /set-cookies` (multiple cookies)

---

## 📜 Logging Behavior

Per-request log files are written to `LOG_DIR` (default `logs/`).

Each log includes:

- request ID + timestamps
- mode
- request and forwarded request sections
- upstream response section
- headers and body previews
- multipart attachment previews

Body preview rules:

- Text-like content: UTF-8 preview
- Binary content: Base64 preview
- Oversized content: truncated with explicit marker

---

## ⚙️ Configuration Reference

### Core

- `MODE` (default `proxy`) values: `proxy`, `idp`
- `LISTEN_HOST` (default `0.0.0.0`)
- `LISTEN_PORT` (default `8080`)
- `LOG_DIR` (default `logs`)
- `MAX_BODY_LOG_BYTES` (default `131072`)
- `REQUEST_TIMEOUT_SECONDS` (default `30`)
- `PRESERVE_HOST_HEADER` (default `false`)

### Routing/Forwarding

- `REQUEST_ENTRY_PATH` (default `/forward/request`)
- `RESPONSE_ENTRY_PATH` (default `/forward/response`)
- `REQUEST_FORWARD_URL` (default `http://mock-request-upstream:18081` in compose)
- `RESPONSE_FORWARD_URL` (default `http://mock-response-upstream:18082` in compose)

### IdP

- `IDP_POST_URL`
- `IDP_SAML_RESPONSE`
- `IDP_FORM_FIELD_NAME` (default `SAMLResponse`)
- `IDP_RELAY_STATE`
- `IDP_PASSTHROUGH_RELAY_STATE` (default `true`)
- `IDP_EXTRA_FORM_FIELDS` (JSON object string)
- `IDP_SET_COOKIE_NAME`
- `IDP_SET_HEADER_NAME`
- `IDP_BODY_TEMPLATE`
- `IDP_HTTP_STATUS` (default `200`)
- `IDP_CONTENT_TYPE` (default `text/html; charset=utf-8`)

### Mock Service Ports (compose)

- `MOCK_REQUEST_PORT` (default `18081`)
- `MOCK_RESPONSE_PORT` (default `18082`)

---

## 🖥️ Local Python Run (Without Docker)

Install:

```bash
pip install -r requirements.txt
```

Run:

```bash
python main.py
```

Note:

- `main.py` loads `.env` automatically if present

---

## 🧪 Automated Tests

```bash
python -m unittest discover -s tests -v
```

Covers:

- health endpoint
- route boundary matching
- proxy forwarding behavior
- duplicate `Set-Cookie` preservation
- idp-mode static response behavior
- attachment preview logging

---

## 📬 Postman Suite

Use files in [`postman/`](postman):

- `RequestCaptureProxy.postman_collection.json`
- `RequestCaptureProxy.local.postman_environment.json`

Guide:

- see [`postman/README.md`](postman/README.md)

Collection covers:

- health checks
- request and response branch forwarding
- multipart and binary requests
- large payload truncation behavior
- idp-mode validation flow

---

## 🩺 Troubleshooting

- ❗ Seeing unexpected upstream target?
  - Check `.env` values for `REQUEST_FORWARD_URL` / `RESPONSE_FORWARD_URL`
  - Run `docker compose config` to inspect resolved values

- ❗ Service starts but forwarding fails?
  - Confirm `MODE=proxy`
  - Confirm upstream URL is reachable from container network
  - Check `docker compose logs request-capture-proxy -f`

- ❗ Not sure which service is which?
  - Read startup banners in `docker compose logs -f`
  - Each container prints `[startup] service=...` with local URLs

- ❗ No logs created?
  - Verify `./logs` bind mount exists and is writable
  - Check `LOG_DIR` value in runtime environment

---

## 🔐 Notes

- This tool is intentionally permissive for debugging.
- IdP mode intentionally performs no SAML validation.
- Do not expose this service to untrusted networks without additional controls.
