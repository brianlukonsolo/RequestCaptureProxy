import base64
import tempfile
import unittest
import zlib
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from urllib3._collections import HTTPHeaderDict

import main


class FakeUpstreamResponse:
    def __init__(self, status_code, content, header_items):
        self.status_code = status_code
        self.content = content
        self.headers = {}
        raw_headers = HTTPHeaderDict()
        for key, value in header_items:
            self.headers[key] = value
            raw_headers.add(key, value)
        self.raw = type("RawHeaders", (), {"headers": raw_headers})()


class StubSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, method, url, headers, data, timeout, allow_redirects):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "data": data,
                "timeout": timeout,
                "allow_redirects": allow_redirects,
            }
        )
        return self.response


class FailingSession:
    def request(self, *args, **kwargs):
        raise AssertionError("HTTP.request should not be called in idp mode")


class RequestCaptureProxyTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_config = main.CONFIG
        self.original_http = main.HTTP
        self.client = main.APP.test_client()

    def tearDown(self):
        main.CONFIG = self.original_config
        main.HTTP = self.original_http
        self.temp_dir.cleanup()

    def set_config(self, **overrides):
        main.CONFIG = replace(main.CONFIG, log_dir=Path(self.temp_dir.name), **overrides)
        main.CONFIG.log_dir.mkdir(parents=True, exist_ok=True)

    def test_health_endpoint(self):
        self.set_config(mode="proxy")
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")
        self.assertEqual(response.get_json()["mode"], "proxy")

    def test_route_prefix_matching_requires_path_boundary(self):
        self.set_config(
            request_forward_url="https://req.example.com",
            response_forward_url="https://resp.example.com",
            request_entry_path="/forward/request",
            response_entry_path="/forward/response",
        )
        req_target, req_suffix = main.resolve_forward_target("forward/request/acs")
        self.assertEqual(req_target, "https://req.example.com")
        self.assertEqual(req_suffix, "/acs")

        fallback_target, fallback_suffix = main.resolve_forward_target("forward/requestevil")
        self.assertEqual(fallback_target, "https://req.example.com")
        self.assertEqual(fallback_suffix, "/forward/requestevil")

        resp_target, resp_suffix = main.resolve_forward_target("forward/response/callback")
        self.assertEqual(resp_target, "https://resp.example.com")
        self.assertEqual(resp_suffix, "/callback")

    def test_saml_instance_aliases_forward_to_request_and_response_targets(self):
        self.set_config(
            request_forward_url="https://idp.example.com/sso",
            response_forward_url="https://sp.example.com/acs",
            saml_instance_sso_path="/saml/instance/sso",
            saml_instance_acs_path="/saml/instance/acs",
        )

        sso_target, sso_suffix = main.resolve_forward_target("saml/instance/sso")
        self.assertEqual(sso_target, "https://idp.example.com/sso")
        self.assertEqual(sso_suffix, "/")

        sso_sub_target, sso_sub_suffix = main.resolve_forward_target("saml/instance/sso/login")
        self.assertEqual(sso_sub_target, "https://idp.example.com/sso")
        self.assertEqual(sso_sub_suffix, "/login")

        acs_target, acs_suffix = main.resolve_forward_target("saml/instance/acs")
        self.assertEqual(acs_target, "https://sp.example.com/acs")
        self.assertEqual(acs_suffix, "/")

    def test_saml_instance_ui_shows_copyable_instance_urls_and_targets(self):
        self.set_config(
            request_forward_url="https://idp.example.com/sso",
            response_forward_url="https://sp.example.com/acs",
            saml_instance_sso_path="/saml/instance/sso",
            saml_instance_acs_path="/saml/instance/acs",
        )

        response = self.client.get("/ui/saml-instance", headers={"Host": "proxy.local:8080"})

        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn("SAML Instance Integration", response_text)
        self.assertIn("http://proxy.local:8080/saml/instance/sso", response_text)
        self.assertIn("http://proxy.local:8080/saml/instance/acs", response_text)
        self.assertIn("https://idp.example.com/sso", response_text)
        self.assertIn("https://sp.example.com/acs", response_text)

    def test_saml_instance_sso_endpoint_forwards_real_instance_request(self):
        self.set_config(
            mode="proxy",
            request_forward_url="https://idp.example.com/sso",
            response_forward_url="https://sp.example.com/acs",
            saml_instance_sso_path="/saml/instance/sso",
            saml_instance_acs_path="/saml/instance/acs",
            request_timeout_seconds=5.0,
        )
        fake_upstream = FakeUpstreamResponse(
            status_code=200,
            content=b"idp-ok",
            header_items=[("Content-Type", "text/plain")],
        )
        stub_session = StubSession(fake_upstream)
        main.HTTP = stub_session

        response = self.client.post(
            "/saml/instance/sso?from=ui",
            data={"SAMLRequest": "instance-request", "RelayState": "relay-instance"},
            headers={"Host": "proxy.local:8080"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b"idp-ok")
        self.assertEqual(len(stub_session.calls), 1)
        call = stub_session.calls[0]
        self.assertEqual(call["url"], "https://idp.example.com/sso?from=ui")
        self.assertIn(b"SAMLRequest=instance-request", call["data"])
        self.assertIn(b"RelayState=relay-instance", call["data"])

        logs = list(Path(self.temp_dir.name).glob("*.log"))
        self.assertEqual(len(logs), 1)
        log_text = logs[0].read_text(encoding="utf-8")
        self.assertIn("REQUEST START", log_text)
        self.assertIn("FORWARDED REQUEST", log_text)
        self.assertIn("SAMLRequest=instance-request", log_text)

    def test_saml_instance_acs_endpoint_forwards_real_instance_response(self):
        self.set_config(
            mode="proxy",
            request_forward_url="https://idp.example.com/sso",
            response_forward_url="https://sp.example.com/acs",
            saml_instance_sso_path="/saml/instance/sso",
            saml_instance_acs_path="/saml/instance/acs",
        )
        fake_upstream = FakeUpstreamResponse(
            status_code=204,
            content=b"",
            header_items=[("Content-Type", "text/plain")],
        )
        stub_session = StubSession(fake_upstream)
        main.HTTP = stub_session

        response = self.client.post(
            "/saml/instance/acs",
            data={"SAMLResponse": "instance-response", "RelayState": "relay-instance"},
        )

        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(stub_session.calls), 1)
        call = stub_session.calls[0]
        self.assertEqual(call["url"], "https://sp.example.com/acs")
        self.assertIn(b"SAMLResponse=instance-response", call["data"])
        self.assertIn(b"RelayState=relay-instance", call["data"])

    def test_proxy_mode_forwards_and_preserves_duplicate_set_cookie_headers(self):
        self.set_config(
            mode="proxy",
            request_forward_url="https://req.example.com",
            response_forward_url="https://resp.example.com/base",
            request_entry_path="/forward/request",
            response_entry_path="/forward/response",
            preserve_host_header=False,
            request_timeout_seconds=9.5,
            max_body_log_bytes=2048,
        )
        fake_upstream = FakeUpstreamResponse(
            status_code=201,
            content=b"upstream-body",
            header_items=[
                ("Content-Type", "text/plain"),
                ("Set-Cookie", "a=1"),
                ("Set-Cookie", "b=2"),
                ("Connection", "close"),
            ],
        )
        stub_session = StubSession(fake_upstream)
        main.HTTP = stub_session

        response = self.client.post(
            "/forward/response/acs?x=1",
            data=b"inbound-payload",
            headers={"Content-Type": "text/plain", "X-Test": "ok", "Host": "example.local"},
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data, b"upstream-body")
        self.assertEqual(response.headers.getlist("Set-Cookie"), ["a=1", "b=2"])
        self.assertFalse("Connection" in response.headers)

        self.assertEqual(len(stub_session.calls), 1)
        call = stub_session.calls[0]
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["url"], "https://resp.example.com/base/acs?x=1")
        self.assertEqual(call["data"], b"inbound-payload")
        self.assertEqual(call["timeout"], 9.5)
        self.assertFalse(call["allow_redirects"])
        self.assertNotIn("Host", call["headers"])
        self.assertNotIn("Content-Length", call["headers"])

        logs = list(Path(self.temp_dir.name).glob("*.log"))
        self.assertEqual(len(logs), 1)
        log_text = logs[0].read_text(encoding="utf-8")
        self.assertIn("REQUEST START", log_text)
        self.assertIn("FORWARDED REQUEST", log_text)
        self.assertIn("RESPONSE END", log_text)

    def test_idp_mode_returns_static_post_cookie_and_header_without_forwarding(self):
        self.set_config(
            mode="idp",
            idp_post_url="https://sp.example.com/saml/acs",
            idp_saml_response="saml-static-value",
            idp_form_field_name="SAMLResponse",
            idp_relay_state="",
            idp_passthrough_relay_state=True,
            idp_extra_form_fields={"tenant": "dev"},
            idp_set_cookie_name="SAMLResponse",
            idp_set_header_name="X-SAML-Response",
            idp_body_template="",
        )
        main.HTTP = FailingSession()

        response = self.client.post("/login", data={"RelayState": "relay-token-123"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-SAML-Response"], "saml-static-value")
        cookies = response.headers.getlist("Set-Cookie")
        self.assertTrue(any(cookie.startswith("SAMLResponse=saml-static-value") for cookie in cookies))

        response_text = response.get_data(as_text=True)
        self.assertIn('action="https://sp.example.com/saml/acs"', response_text)
        self.assertIn('name="SAMLResponse"', response_text)
        self.assertIn('value="saml-static-value"', response_text)
        self.assertIn('name="RelayState"', response_text)
        self.assertIn('value="relay-token-123"', response_text)
        self.assertIn('name="tenant"', response_text)
        self.assertIn('value="dev"', response_text)

        logs = list(Path(self.temp_dir.name).glob("*.log"))
        self.assertEqual(len(logs), 1)
        log_text = logs[0].read_text(encoding="utf-8")
        self.assertIn("IDP STATIC", log_text)

    def test_attachment_preview_is_logged(self):
        self.set_config(max_body_log_bytes=1024)
        boundary = "----boundary123"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="proof.txt"\r\n'
            "Content-Type: text/plain\r\n\r\n"
            "attachment-data\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")

        log = main.RequestFileLog(main.CONFIG, "attachcheck")
        main.log_message_block(
            log=log,
            title="ATTACHMENT TEST",
            method="POST",
            url="http://localhost/test",
            headers=[("Content-Type", f"multipart/form-data; boundary={boundary}")],
            body=body,
        )
        log.close()

        log_text = Path(log.file_path).read_text(encoding="utf-8")
        self.assertIn("Attachments:", log_text)
        self.assertIn("filename=proof.txt", log_text)
        self.assertIn("content_preview", log_text)
        self.assertIn("attachment-data", log_text)

    def test_saml_sender_ui_lists_configured_targets_and_custom_option(self):
        self.set_config(
            saml_request_targets=[
                {"name": "Dev IdP", "url": "https://idp.dev.example.com/sso"},
                {"name": "QA IdP", "url": "https://idp.qa.example.com/sso"},
            ]
        )

        response = self.client.get("/ui/saml-request")

        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn("SAML Request/Response Sender", response_text)
        self.assertIn("Example Generator", response_text)
        self.assertIn("Dev IdP - https://idp.dev.example.com/sso", response_text)
        self.assertIn("QA IdP - https://idp.qa.example.com/sso", response_text)
        self.assertIn("Custom URL", response_text)

    def test_main_ui_is_single_tabbed_page_for_all_modes(self):
        self.set_config(
            request_forward_url="https://idp.example.com/sso",
            response_forward_url="https://sp.example.com/acs",
            saml_request_targets=[{"name": "Demo IdP", "url": "https://idp.example.com/sso"}],
        )

        response = self.client.get("/ui", headers={"Host": "proxy.local:8080"})

        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn("Request Capture Proxy", response_text)
        self.assertIn("data-tab=\"instance\"", response_text)
        self.assertIn("data-tab=\"sender\"", response_text)
        self.assertIn("data-tab=\"status\"", response_text)
        self.assertIn("SAML Instance Integration", response_text)
        self.assertIn("SAML Request/Response Sender", response_text)
        self.assertIn("http://proxy.local:8080/saml/instance/sso", response_text)
        self.assertIn("Proxy SSO URL - http://proxy.local:8080/saml/instance/sso", response_text)
        self.assertIn("Proxy ACS URL - http://proxy.local:8080/saml/instance/acs", response_text)
        self.assertIn("Demo IdP - https://idp.example.com/sso", response_text)

    def test_saml_example_generator_returns_authn_request_xml(self):
        self.set_config()

        response = self.client.post(
            "/saml/example",
            data={
                "kind": "authn_request",
                "issuer": "https://sp.local/metadata",
                "destination": "https://idp.local/sso",
                "acs_url": "https://sp.local/saml/acs",
                "relay_state": "relay-example",
            },
        )

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["field_name"], "SAMLRequest")
        self.assertEqual(data["relay_state"], "relay-example")
        self.assertIn("<samlp:AuthnRequest", data["xml"])
        self.assertIn("https://sp.local/metadata", data["xml"])
        self.assertIn('Destination="https://idp.local/sso"', data["xml"])
        self.assertIn('AssertionConsumerServiceURL="https://sp.local/saml/acs"', data["xml"])

    def test_saml_example_generator_returns_saml_response_xml(self):
        self.set_config()

        response = self.client.post(
            "/saml/example",
            data={
                "kind": "saml_response",
                "issuer": "https://idp.local/metadata",
                "destination": "https://sp.local/saml/acs",
                "audience": "https://sp.local/metadata",
                "name_id": "debug.user@example.com",
                "in_response_to": "_request123",
            },
        )

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["field_name"], "SAMLResponse")
        self.assertIn("<samlp:Response", data["xml"])
        self.assertIn("urn:oasis:names:tc:SAML:2.0:status:Success", data["xml"])
        self.assertIn('InResponseTo="_request123"', data["xml"])
        self.assertIn("debug.user@example.com", data["xml"])
        self.assertIn("<saml:Audience>https://sp.local/metadata</saml:Audience>", data["xml"])

    def test_saml_sender_browser_post_uses_custom_url_and_logs_everything(self):
        self.set_config(max_body_log_bytes=2048)
        saml_xml = '<samlp:AuthnRequest ID="_abc" Version="2.0" />'
        expected_encoded = base64.b64encode(saml_xml.encode("utf-8")).decode("ascii")

        response = self.client.post(
            "/saml/send",
            data={
                "target_choice": "custom",
                "custom_target_url": "https://idp.example.com/sso",
                "binding": "browser_post",
                "input_format": "raw_xml",
                "relay_state": "relay-123",
                "extra_fields_json": '{"ForceAuthn":"true"}',
                "saml_request": saml_xml,
            },
        )

        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn('method="post" action="https://idp.example.com/sso"', response_text)
        self.assertIn('name="SAMLRequest"', response_text)
        self.assertIn(f'value="{expected_encoded}"', response_text)
        self.assertIn('name="RelayState" value="relay-123"', response_text)
        self.assertIn('name="ForceAuthn" value="true"', response_text)

        logs = list(Path(self.temp_dir.name).glob("*.log"))
        self.assertEqual(len(logs), 1)
        log_text = logs[0].read_text(encoding="utf-8")
        self.assertIn("mode=saml_sender", log_text)
        self.assertIn("SAML SEND SOURCE", log_text)
        self.assertIn(saml_xml, log_text)
        self.assertIn("SAML SEND REQUEST", log_text)
        self.assertIn("SAMLRequest=", log_text)

    def test_saml_sender_browser_post_can_send_saml_response_field(self):
        self.set_config(max_body_log_bytes=2048)
        saml_xml = '<samlp:Response ID="_response" Version="2.0" />'
        expected_encoded = base64.b64encode(saml_xml.encode("utf-8")).decode("ascii")

        response = self.client.post(
            "/saml/send",
            data={
                "target_choice": "custom",
                "custom_target_url": "https://sp.example.com/saml/acs",
                "binding": "browser_post",
                "input_format": "raw_xml",
                "payload_field_name": "SAMLResponse",
                "relay_state": "relay-response",
                "extra_fields_json": "{}",
                "saml_request": saml_xml,
            },
        )

        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn('method="post" action="https://sp.example.com/saml/acs"', response_text)
        self.assertIn('name="SAMLResponse"', response_text)
        self.assertIn(f'value="{expected_encoded}"', response_text)

        logs = list(Path(self.temp_dir.name).glob("*.log"))
        self.assertEqual(len(logs), 1)
        log_text = logs[0].read_text(encoding="utf-8")
        self.assertIn("Payload-Field: SAMLResponse", log_text)
        self.assertIn("SAMLResponse=", log_text)

    def test_saml_sender_redirect_uses_preset_and_deflates_raw_xml(self):
        self.set_config(
            saml_request_targets=[
                {"name": "Preset IdP", "url": "https://idp.example.com/sso?existing=1"}
            ]
        )
        saml_xml = '<samlp:AuthnRequest ID="_redirect" Version="2.0" />'

        response = self.client.post(
            "/saml/send",
            data={
                "target_choice": "preset:0",
                "binding": "browser_redirect",
                "input_format": "raw_xml",
                "relay_state": "relay-redirect",
                "extra_fields_json": "{}",
                "saml_request": saml_xml,
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        location = response.headers["Location"]
        parsed = urlparse(location)
        query = parse_qs(parsed.query)
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.netloc, "idp.example.com")
        self.assertEqual(query["existing"], ["1"])
        self.assertEqual(query["RelayState"], ["relay-redirect"])
        inflated = zlib.decompress(base64.b64decode(query["SAMLRequest"][0]), wbits=-15).decode("utf-8")
        self.assertEqual(inflated, saml_xml)

    def test_saml_sender_server_post_sends_form_and_renders_response(self):
        self.set_config(request_timeout_seconds=4.0, max_body_log_bytes=2048)
        fake_upstream = FakeUpstreamResponse(
            status_code=202,
            content=b"accepted",
            header_items=[("Content-Type", "text/plain"), ("X-Upstream", "ok")],
        )
        stub_session = StubSession(fake_upstream)
        main.HTTP = stub_session

        response = self.client.post(
            "/saml/send",
            data={
                "target_choice": "custom",
                "custom_target_url": "https://idp.example.com/sso",
                "binding": "server_post",
                "input_format": "encoded",
                "relay_state": "relay-server",
                "extra_fields_json": '{"SigAlg":"rsa-sha256"}',
                "saml_request": "already-encoded-value",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(stub_session.calls), 1)
        call = stub_session.calls[0]
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["url"], "https://idp.example.com/sso")
        self.assertEqual(call["timeout"], 4.0)
        self.assertFalse(call["allow_redirects"])
        self.assertEqual(call["headers"]["Content-Type"], "application/x-www-form-urlencoded")
        self.assertIn(b"SAMLRequest=already-encoded-value", call["data"])
        self.assertIn(b"RelayState=relay-server", call["data"])
        self.assertIn(b"SigAlg=rsa-sha256", call["data"])

        response_text = response.get_data(as_text=True)
        self.assertIn("Server POST Result", response_text)
        self.assertIn("202", response_text)
        self.assertIn("accepted", response_text)


if __name__ == "__main__":
    unittest.main()
