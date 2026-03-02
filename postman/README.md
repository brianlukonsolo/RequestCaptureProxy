# Postman Test Suite

## Files

- `RequestCaptureProxy.postman_collection.json`: comprehensive request set
- `RequestCaptureProxy.local.postman_environment.json`: local variables
- `payloads/sample-upload.txt`: multipart file upload payload
- `payloads/sample-binary.bin`: binary upload payload

## Import

1. Import both JSON files into Postman.
2. Select environment `RequestCaptureProxy Local`.
3. Ensure the proxy is running on `http://localhost:8080`.

## Recommended runtime config for proxy-mode tests

Set these in `.env` (or `docker-compose.yml`) before starting service:

- `MODE=proxy`
- `REQUEST_FORWARD_URL=http://mock-request-upstream:18081`
- `RESPONSE_FORWARD_URL=http://mock-response-upstream:18082`

Then run folders in this order:

1. `00 - Health`
2. `10 - Proxy Mode - Request Forwarding`
3. `20 - Proxy Mode - Response Forwarding`
4. `30 - Proxy Mode - Log Formatting and Truncation`

## Runtime config for idp-mode tests

Set these in `.env` (or `docker-compose.yml`) before starting service:

- `MODE=idp`
- `IDP_POST_URL=https://sp.example.com/saml/acs`
- `IDP_SAML_RESPONSE=<your static saml response>`
- Optionally set `IDP_SET_COOKIE_NAME`, `IDP_SET_HEADER_NAME`, `IDP_BODY_TEMPLATE`

In Postman environment, change:

- `mode=idp`
- `idp_form_field_name` (if changed in service config)
- `idp_cookie_name` and `idp_header_name` to match active settings
- `idp_template_expected_text` if you want strict template assertion

Run folder:

1. `40 - IdP Mode`

## What to verify in log files

Logs are written to `logs/` (one file per request). Verify:

- request boundaries (`REQUEST START`, `FORWARDED REQUEST`, `RESPONSE END`)
- headers and bodies captured
- multipart attachment preview lines are present
- binary payloads/responses logged in base64
- large body request contains truncation marker
