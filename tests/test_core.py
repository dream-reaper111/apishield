import json
import tempfile
import unittest
from pathlib import Path

from apishield.core import SpecError, analyze, analyze_file


def spec():
    return {"openapi": "3.1.0", "info": {"title": "isolated test", "version": "1"},
            "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
            "security": [{"bearer": []}],
            "paths": {"/items/{id}": {"parameters": [{"name": "id", "in": "path", "required": True,
                                                       "schema": {"type": "string"}}],
                                      "get": {"responses": {"200": {"description": "test"}}},
                                      "post": {"security": [], "responses": {"201": {"description": "test"}}}}}}


class CoreTests(unittest.TestCase):
    def test_global_security_and_explicit_override(self):
        report = analyze(json.dumps(spec()).encode(), ".json")
        self.assertFalse(report["operations"][0]["anonymous_permitted_by_spec"])
        self.assertTrue(report["operations"][1]["anonymous_permitted_by_spec"])
        self.assertEqual(len(report["authorization_review_matrix"]), 2)
        self.assertEqual(report["network_requests"], 0)

    def test_optional_auth_and_query_key_review(self):
        document = spec()
        document["security"] = [{}, {"bearer": []}]
        document["components"]["securitySchemes"]["querykey"] = {"type": "apiKey", "in": "query", "name": "key"}
        report = analyze(json.dumps(document).encode(), ".json")
        self.assertTrue(report["operations"][0]["anonymous_permitted_by_spec"])
        self.assertIn("query_api_key", report["findings_for_review"][0]["type"])

    def test_duplicate_json_and_external_ref_not_resolved(self):
        with self.assertRaises(SpecError):
            analyze(b'{"openapi":"3.1.0","openapi":"3.0.0"}', ".json")
        document = spec()
        document["paths"]["/items/{id}"]["parameters"] = [{"$ref": "https://example.invalid/param"}]
        report = analyze(json.dumps(document).encode(), ".json")
        self.assertIn("not resolved", " ".join(report["issues"]))

    def test_yaml_alias_rejected_when_yaml_available(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML unavailable")
        with self.assertRaises(SpecError):
            analyze(b"openapi: &v 3.1.0\ninfo: {title: *v}\npaths: {}\n", ".yaml")

    def test_cli_file_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "api.json"
            path.write_text(json.dumps(spec()))
            report = analyze_file(path)
        self.assertEqual(len(report["operations"]), 2)
        self.assertEqual(len(report["source_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
