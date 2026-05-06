import contextlib
import importlib.util
import io
import unittest
from pathlib import Path


DEMO_LOGGER_PATH = Path(__file__).resolve().parents[1] / "demo" / "request_logger.py"
SPEC = importlib.util.spec_from_file_location("demo_request_logger", DEMO_LOGGER_PATH)
demo_request_logger = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(demo_request_logger)


class DemoRequestLoggerTests(unittest.TestCase):
    def setUp(self):
        self.client = demo_request_logger.APP.test_client()

    def test_health_endpoint(self):
        response = self.client.get("/healthz")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")
        self.assertEqual(response.get_json()["service"], "demo-request-logger")

    def test_logs_and_echoes_request_snapshot(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            response = self.client.post(
                "/saml/acs?demo=1",
                data="SAMLResponse=demo-response&RelayState=relay-123",
                headers={"Content-Type": "application/x-www-form-urlencoded", "X-Demo": "ok"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Demo-Request-Logger"], "demo-request-logger")
        payload = response.get_json()
        self.assertEqual(payload["method"], "POST")
        self.assertEqual(payload["path"], "/saml/acs")
        self.assertEqual(payload["args"]["demo"], ["1"])
        self.assertEqual(payload["form"]["RelayState"], ["relay-123"])
        self.assertIn("SAMLResponse=demo-response", payload["body"]["preview"])

        log_text = stdout.getvalue()
        self.assertIn("[demo-request] method=POST", log_text)
        self.assertIn("[demo-request] url=http://localhost/saml/acs?demo=1", log_text)
        self.assertIn("X-Demo: ok", log_text)
        self.assertIn("SAMLResponse=demo-response", log_text)


if __name__ == "__main__":
    unittest.main()
