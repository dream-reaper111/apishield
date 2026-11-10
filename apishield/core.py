"""Bounded, passive OpenAPI 3.x inventory and evidence-backed review cues."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

MAX_BYTES = 4 * 1024 * 1024
MAX_PATHS = 2000
METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


class SpecError(ValueError):
    pass


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SpecError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load(raw: bytes, suffix: str) -> dict:
    if not 0 < len(raw) <= MAX_BYTES:
        raise SpecError("specification must be 1 to 4 MiB")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SpecError("specification must use UTF-8") from exc
    if suffix.lower() == ".json":
        try:
            data = json.loads(text, object_pairs_hook=_unique_pairs)
        except json.JSONDecodeError as exc:
            raise SpecError("invalid JSON") from exc
    elif suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as exc:
            raise SpecError("PyYAML is unavailable; use OpenAPI JSON") from exc

        class Loader(yaml.SafeLoader):
            def __init__(self, stream):
                super().__init__(stream)
                self.depth = 0
                self.nodes_seen = 0

            def compose_node(self, parent, index):
                if self.check_event(yaml.AliasEvent):
                    raise SpecError("YAML aliases are not accepted")
                self.depth += 1
                self.nodes_seen += 1
                if self.depth > 48 or self.nodes_seen > 50000:
                    raise SpecError("YAML complexity limit exceeded")
                try:
                    return super().compose_node(parent, index)
                finally:
                    self.depth -= 1

            def construct_mapping(self, node, deep=False):
                result = {}
                for key_node, value_node in node.value:
                    key = self.construct_object(key_node, deep=deep)
                    if not isinstance(key, str) or key in result:
                        raise SpecError("duplicate or non-string YAML key")
                    result[key] = self.construct_object(value_node, deep=deep)
                return result

        try:
            data = yaml.load(text, Loader=Loader)
        except yaml.YAMLError as exc:
            raise SpecError("invalid YAML") from exc
    else:
        raise SpecError("input must be .json, .yaml, or .yml")
    if not isinstance(data, dict):
        raise SpecError("OpenAPI document must be a mapping")
    return data


def _security(value, schemes: dict, location: str, issues: list[str]) -> tuple[list[dict], bool]:
    if not isinstance(value, list):
        issues.append(f"{location}: security must be a list")
        return [], False
    alternatives = []
    anonymous = not value
    for index, requirement in enumerate(value):
        if not isinstance(requirement, dict):
            issues.append(f"{location}: security alternative {index} is not a mapping")
            continue
        if not requirement:
            anonymous = True
            continue
        resolved = {}
        for name, scopes in requirement.items():
            if name not in schemes:
                issues.append(f"{location}: undefined security scheme {name}")
            if not isinstance(scopes, list) or any(not isinstance(s, str) for s in scopes):
                issues.append(f"{location}: invalid scopes for {name}")
            resolved[name] = scopes
        alternatives.append(resolved)
    return alternatives, anonymous


def analyze(raw: bytes, suffix: str) -> dict:
    data = _load(raw, suffix)
    version = data.get("openapi")
    if not isinstance(version, str) or not re.fullmatch(r"3\.[01](?:\.\d+)?", version):
        raise SpecError("only OpenAPI 3.0 and 3.1 documents are supported")
    paths = data.get("paths")
    if not isinstance(paths, dict) or len(paths) > MAX_PATHS:
        raise SpecError("paths must be a mapping with at most 2000 entries")
    components = data.get("components", {})
    if not isinstance(components, dict):
        raise SpecError("components must be a mapping")
    schemes = components.get("securitySchemes", {})
    if not isinstance(schemes, dict):
        raise SpecError("securitySchemes must be a mapping")
    issues = []
    findings = []
    operations = []
    matrix = []
    global_security = data.get("security", None)
    for name, scheme in schemes.items():
        if not isinstance(scheme, dict):
            issues.append(f"security scheme {name}: invalid mapping")
            continue
        if scheme.get("type") == "apiKey" and scheme.get("in") == "query":
            findings.append({"type": "query_api_key_configuration_review", "evidence": f"#/components/securitySchemes/{name}",
                             "owasp_reference": "API2:2023",
                             "interpretation": "query-carried API key is declared; exposure in logs or URLs needs review, not confirmed"})
    for path, path_item in paths.items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(path_item, dict):
            issues.append(f"invalid path item: {str(path)[:80]}")
            continue
        if "$ref" in path_item:
            issues.append(f"{path}: path-level $ref is not resolved")
            continue
        path_parameters = path_item.get("parameters", [])
        if not isinstance(path_parameters, list):
            issues.append(f"{path}: path parameters must be a list")
            path_parameters = []
        for method, operation in path_item.items():
            if method not in METHODS:
                continue
            reference = f"#/paths/{path.replace('~', '~0').replace('/', '~1')}/{method}"
            if not isinstance(operation, dict):
                issues.append(f"{reference}: operation is not a mapping")
                continue
            security = operation["security"] if "security" in operation else global_security
            if security is None:
                alternatives, anonymous = [], True
                declared = False
            else:
                alternatives, anonymous = _security(security, schemes, reference, issues)
                declared = True
            if anonymous:
                findings.append({"type": "anonymous_access_specification_review", "evidence": reference + "/security",
                                 "owasp_reference": "API2:2023",
                                 "interpretation": "specification permits or does not declare authentication; runtime access not tested"})
            params = path_parameters + operation.get("parameters", []) if isinstance(operation.get("parameters", []), list) else path_parameters
            normalized_params = []
            for param in params:
                if not isinstance(param, dict) or "$ref" in param:
                    issues.append(f"{reference}: parameter reference or layout not resolved")
                    continue
                name = param.get("name")
                location = param.get("in")
                if not isinstance(name, str) or location not in {"path", "query", "header", "cookie"}:
                    issues.append(f"{reference}: invalid parameter declaration")
                    continue
                if "schema" not in param and "content" not in param:
                    issues.append(f"{reference}: parameter {name} has no schema or content")
                schema = param.get("schema") if isinstance(param.get("schema"), dict) else {}
                normalized_params.append({"name": name, "in": location,
                                          "required": bool(param.get("required", False)),
                                          "schema_ref": schema.get("$ref"),
                                          "schema_type": schema.get("type") if isinstance(schema.get("type"), (str, list)) else None})
            path_vars = set(re.findall(r"\{([^{}]+)\}", path))
            declared_vars = {p["name"] for p in normalized_params if p["in"] == "path"}
            for missing in sorted(path_vars - declared_vars):
                issues.append(f"{reference}: undeclared path parameter {missing}")
            operations.append({"method": method.upper(), "path": path, "evidence": reference,
                               "security_declared": declared, "anonymous_permitted_by_spec": anonymous,
                               "security_alternatives": alternatives, "parameters": normalized_params,
                               "request_body_declared": "requestBody" in operation,
                               "request_body_media_types": sorted(operation.get("requestBody", {}).get("content", {}))
                               if isinstance(operation.get("requestBody"), dict)
                               and isinstance(operation["requestBody"].get("content"), dict) else []})
            for object_id in sorted(path_vars):
                matrix.append({"operation": f"{method.upper()} {path}", "object_parameter": object_id,
                               "review_cases": ["same_owner", "different_owner", "different_tenant", "anonymous"],
                               "owasp_reference": "API1:2023",
                               "status": "manual_review_only",
                               "interpretation": "object-level authorization cannot be proven from an OpenAPI specification"})
            if len(operations) > 10000:
                raise SpecError("operation count exceeds 10000")
    return {"schema_version": 1, "openapi_version": version,
            "source_sha256": hashlib.sha256(raw).hexdigest(), "operations": operations,
            "security_schemes": sorted(schemes), "findings_for_review": findings,
            "authorization_review_matrix": matrix, "issues": issues,
            "network_requests": 0, "assessment_limit": "specification review only; no live API tested"}


def analyze_file(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise SpecError("input must be a regular specification file of at most 4 MiB")
    return analyze(path.read_bytes(), path.suffix)
