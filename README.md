# 🧭 Request Capture Proxy

Debug SAML/API-gateway flows by logging the real HTTP traffic end to end.

The main thing to remember:

```text
http://localhost:8080/ui
```

That single UI has tabs for:

- 🧩 `Instance Setup` - copy the SSO/ACS URLs into your SAML product UI.
- 🪄 `Send / Generate` - generate or paste SAMLRequest/SAMLResponse payloads and send them.
- ✅ `Status` - health checks and proof commands.

> ⚠️ This tool intentionally logs sensitive SAML and HTTP data. Use it for debugging, not as an internet-facing service.

## 🚦 Pick Your Run Mode

| Mode | Use It When | Command |
| --- | --- | --- |
| 🧍 Standalone | You want only the proxy and will configure real upstreams yourself. | `docker compose up --build -d` |
| 🎬 Demo | You want a visible proof server that logs every forwarded request. | `docker compose -f docker-compose.yml -f docker-compose.demo.yml up --build -d` |
| 🐍 Local Python | You are developing or debugging without Docker. | `python main.py` |

## ⚡ Quick Start

1. Create your local config:

```powershell
Copy-Item .env.example .env
```

2. Start demo mode:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml up --build -d
```

3. Open the UI:

```text
http://localhost:8080/ui
```

4. Open the demo logger stream:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml logs -f demo-request-logger
```

5. In the UI, use `Instance Setup` → `Send To SSO URL` or `Send To ACS URL`.

You should see:

- 📁 a new capture file in `logs/`
- 🖥️ a matching request printed by `demo-request-logger`

## 🎬 Demo Mode For Showcases

Demo mode starts two services:

- 🚪 `request-capture-proxy` at `http://localhost:8080`
- 📣 `demo-request-logger` at `http://localhost:18080`

The proxy forwards both branches to the demo logger:

```env
REQUEST_FORWARD_URL=http://demo-request-logger:18080
RESPONSE_FORWARD_URL=http://demo-request-logger:18080
```

Start:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml up --build -d
```

Watch requests arrive:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml logs -f demo-request-logger
```

Send a proof request:

```bash
curl -X POST "http://localhost:8080/forward/request/saml/login?demo=1" -H "Content-Type: application/x-www-form-urlencoded" -d "SAMLRequest=demo-request&RelayState=relay-123"
```

Send a proof response:

```bash
curl -X POST "http://localhost:8080/forward/response/saml/acs" -H "Content-Type: application/x-www-form-urlencoded" -d "SAMLResponse=demo-response&RelayState=relay-123"
```

PowerShell note:

```powershell
curl.exe -X POST "http://localhost:8080/forward/request/saml/login?demo=1" -H "Content-Type: application/x-www-form-urlencoded" -d "SAMLRequest=demo-request&RelayState=relay-123"
```

Stop:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml down
```

## 🧍 Standalone Proxy

Use this when you want the proxy only.

Start:

```bash
docker compose up --build -d
```

Open:

```text
http://localhost:8080/ui
```

Set real forwarding targets in `.env`:

```env
REQUEST_FORWARD_URL=https://real-idp.example.com/sso
RESPONSE_FORWARD_URL=https://real-sp.example.com/saml/acs
```

Follow proxy logs:

```bash
docker compose logs -f request-capture-proxy
```

Stop:

```bash
docker compose down
```

## 🧩 Sending From A SAML Product UI

Open:

```text
http://localhost:8080/ui
```

Go to the `Instance Setup` tab.

Copy these into your SAML product:

- 🔐 IdP SSO / Login URL:
  `http://localhost:8080/saml/instance/sso`
- 📬 SP ACS / Callback URL:
  `http://localhost:8080/saml/instance/acs`

How it works:

- Requests sent to `/saml/instance/sso` are logged, then forwarded to `REQUEST_FORWARD_URL`.
- Responses sent to `/saml/instance/acs` are logged, then forwarded to `RESPONSE_FORWARD_URL`.

Optional custom paths:

```env
SAML_INSTANCE_SSO_PATH=/saml/instance/sso
SAML_INSTANCE_ACS_PATH=/saml/instance/acs
```

## 🪄 Generate And Send SAML

Open:

```text
http://localhost:8080/ui
```

Go to the `Send / Generate` tab.

You can:

- 🧾 generate a sample `AuthnRequest`
- 🎟️ generate a sample `SAMLResponse`
- ✍️ paste your own SAML payload
- 🚀 send using Browser POST, Browser Redirect, or Server POST

Default destinations are proxy URLs:

- `Proxy SSO URL` → logs through the proxy and forwards to `REQUEST_FORWARD_URL`
- `Proxy ACS URL` → logs through the proxy and forwards to `RESPONSE_FORWARD_URL`

`idp.example.com` only appears inside sample XML. It is not the default send target.

Optional sender presets:

```env
SAML_REQUEST_TARGETS={"Dev IdP":"https://idp.dev.example.com/sso","QA IdP":"https://idp.qa.example.com/sso"}
```

Delimited format also works:

```env
SAML_REQUEST_TARGETS=Dev=https://idp.dev.example.com/sso;QA=https://idp.qa.example.com/sso
```

## ✅ How To Know It Works

1. Health returns JSON:

```bash
curl http://localhost:8080/healthz
```

Expected fields:

```json
{"status":"ok","mode":"proxy"}
```

2. Demo logger receives forwarded traffic:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml logs demo-request-logger
```

Look for:

```text
[demo-request] method=POST
[demo-request] body_preview:
  SAMLRequest=demo-request&RelayState=relay-123
```

3. Proxy writes capture files:

```powershell
Get-ChildItem .\logs | Sort-Object LastWriteTime -Descending | Select-Object -First 5
```

Open the newest `.log` and look for:

- `REQUEST START`
- `FORWARDED REQUEST`
- `RESPONSE END`

## 🐍 Local Python Run

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the local demo logger:

```bash
python demo/request_logger.py
```

In another terminal, make sure `.env` points to the local logger:

```env
REQUEST_FORWARD_URL=http://127.0.0.1:18080
RESPONSE_FORWARD_URL=http://127.0.0.1:18080
```

Start the proxy:

```bash
python main.py
```

Open:

```text
http://localhost:8080/ui
```

The `Instance Setup` proof buttons should return JSON from the local demo logger and create capture files in `logs/`.

## ⚙️ Configuration Cheat Sheet

Core:

```env
MODE=proxy
LISTEN_HOST=0.0.0.0
LISTEN_PORT=8080
LOG_DIR=logs
MAX_BODY_LOG_BYTES=131072
REQUEST_TIMEOUT_SECONDS=30
PRESERVE_HOST_HEADER=false
```

Forwarding:

```env
REQUEST_ENTRY_PATH=/forward/request
RESPONSE_ENTRY_PATH=/forward/response
SAML_INSTANCE_SSO_PATH=/saml/instance/sso
SAML_INSTANCE_ACS_PATH=/saml/instance/acs
REQUEST_FORWARD_URL=
RESPONSE_FORWARD_URL=
```

Fake IdP mode:

```env
MODE=idp
IDP_POST_URL=https://sp.example.com/saml/acs
IDP_SAML_RESPONSE=<Base64OrRawSamlResponseHere>
IDP_FORM_FIELD_NAME=SAMLResponse
IDP_PASSTHROUGH_RELAY_STATE=true
```

Demo:

```env
DEMO_REQUEST_LOGGER_PORT=18080
DEMO_MAX_BODY_LOG_BYTES=8192
```

## 📣 Demo Request Logger

The demo request logger lives in:

- `demo/request_logger.py`
- `demo/Dockerfile`

It exposes:

- `GET /healthz`
- `GET|POST|PUT|PATCH|DELETE /...`

It prints:

- request ID and timestamp
- method and full URL
- headers
- parsed form fields
- body size
- text/base64 body preview

It also returns the captured request snapshot as JSON.

## 🧪 Tests

```bash
python -m unittest discover -s tests -v
```

Covers:

- health endpoint
- route boundary matching
- proxy forwarding
- duplicate `Set-Cookie` preservation
- IdP static response behavior
- attachment preview logging
- tabbed UI behavior
- SAML generator/sender behavior
- SAML instance endpoint forwarding
- demo request logger behavior

## 📬 Postman

Use:

- `postman/RequestCaptureProxy.postman_collection.json`
- `postman/RequestCaptureProxy.local.postman_environment.json`

For proxy-mode Postman runs, start demo mode first:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml up --build -d
```

## 🧯 Troubleshooting

### ❌ It tries to call `idp.example.com`

That should only happen if you selected a custom/preset target that points there. The default destination should be `Proxy SSO URL` or `Proxy ACS URL`.

Check `.env`:

```env
SAML_REQUEST_TARGETS=
```

Restart the app after editing `.env`.

### ❌ It tries to call `mock-request-upstream`

That is an old Docker-only hostname. Remove stale shell variables or use `.env` targets:

```env
REQUEST_FORWARD_URL=http://127.0.0.1:18080
RESPONSE_FORWARD_URL=http://127.0.0.1:18080
```

### ❌ No capture files appear

Check:

- `LOG_DIR=logs`
- the `logs/` folder is writable
- the request is going through the proxy URL, not directly to the target

## 🔐 Safety Notes

- This tool is intentionally permissive for debugging.
- It logs SAML payloads, cookies, headers, and bodies by design.
- Do not expose it to untrusted networks without additional controls.
