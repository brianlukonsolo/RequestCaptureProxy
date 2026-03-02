import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
