# Request Capture Proxy

Debug helper for SAML/API-gateway flows with two modes:

- `proxy`: forwards traffic and logs complete request/response details.
- `idp`: returns a static SAML response immediately (no validation), including auto-POST to a configured endpoint.

## Features

- Logs each interaction to a separate file in `LOG_DIR`.
- Captures:
  - all headers
  - full body (truncated by `MAX_BODY_LOG_BYTES`)
  - multipart attachments metadata plus content preview
- Clear section boundaries in logs:
  - `REQUEST START`
  - `FORWARDED REQUEST`
  - `RESPONSE END`
- Two configurable forwarding targets:
  - `REQUEST_FORWARD_URL`
  - `RESPONSE_FORWARD_URL`
- Configurable local entry routes:
  - `REQUEST_ENTRY_PATH` (default `/forward/request`)
  - `RESPONSE_ENTRY_PATH` (default `/forward/response`)

## Install

```bash
pip install -r requirements.txt
```

## Run With Docker Compose

1. Optional runtime config file:

```powershell
Copy-Item .env.example .env
```

2. Update `.env` values for either `MODE=proxy` or `MODE=idp`.

3. Start:

```bash
docker compose up --build -d
```

4. View logs:

```bash
docker compose logs -f
```

Startup banners now print explicit service identity and URLs for:

- `request-capture-proxy`
- `mock-request-upstream`
- `mock-response-upstream`

5. Stop:

```bash
docker compose down
```

Configuration sources:

- `.env` (Compose variable interpolation)
- inline overrides in `docker-compose.yml` under `environment`
- container health endpoint: `GET /healthz`

By default, compose starts three services:

- `request-capture-proxy` on `http://localhost:8080`
- `mock-request-upstream` on `http://localhost:18081`
- `mock-response-upstream` on `http://localhost:18082`

Forwarding defaults:

- `REQUEST_FORWARD_URL=http://mock-request-upstream:18081`
- `RESPONSE_FORWARD_URL=http://mock-response-upstream:18082`

## Run

```bash
python main.py
```

## Test

```bash
python -m unittest discover -s tests -v
```

## Proxy Mode

Set:

- `MODE=proxy`
- `REQUEST_FORWARD_URL=https://idp.example.com`
- `RESPONSE_FORWARD_URL=https://sp.example.com`

Then call:

- `http://localhost:8080/forward/request/...` -> forwards to `REQUEST_FORWARD_URL/...`
- `http://localhost:8080/forward/response/...` -> forwards to `RESPONSE_FORWARD_URL/...`

Any other path falls back to `REQUEST_FORWARD_URL`.

### Built-in Mock Upstream Endpoints (compose)

Available on both mock services:

- `GET /healthz`
- `GET|POST|PUT|PATCH|DELETE /...` (echo JSON response with request details)
- `GET /image/png` (binary payload)
- `GET /response-headers?Set-Cookie=a%3D1&Set-Cookie=b%3D2` (duplicate headers test)
- `GET /status/<code>` (custom status code)
- `GET /set-cookies` (multiple cookies)

## IdP Mode

Set:

- `MODE=idp`
- `IDP_POST_URL=https://sp.example.com/saml/acs`
- `IDP_SAML_RESPONSE=<your static SAMLResponse>`

Behavior:

- Incoming request is accepted as-is.
- No validation/signature checks are performed.
- Response is returned as an auto-submitting HTML form POST to `IDP_POST_URL`.

Optional placement of SAML response:

- Form field name: `IDP_FORM_FIELD_NAME` (default `SAMLResponse`)
- Cookie: set `IDP_SET_COOKIE_NAME=SAMLResponse`
- Header: set `IDP_SET_HEADER_NAME=SomeHeader`
- Custom body template: `IDP_BODY_TEMPLATE`. Supported placeholders are `{{SAML_RESPONSE}}`, `{{POST_URL}}`, `{{FORM_FIELD_NAME}}`, `{{RELAY_STATE}}`, `{{FORM_FIELDS_JSON}}`.

RelayState handling:

- `IDP_PASSTHROUGH_RELAY_STATE=true` forwards inbound `RelayState` when present.
- Fallback static value: `IDP_RELAY_STATE`.

## Notes

- `MAX_BODY_LOG_BYTES` controls how much of request/response body is written to logs.
- Binary bodies are logged as Base64.
- Multipart attachment payloads are previewed in the same request log file.
