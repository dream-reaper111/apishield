# APIShield

APIShield's first milestone performs a **passive, offline** security review of an authorized OpenAPI 3.0 or 3.1 document. It inventories operations and parameters, applies top-level and operation-level security declarations, identifies anonymous access documented by the specification, flags query-carried API keys for review, and generates an object-authorization review matrix. It makes **zero network requests** to the described API. Configuration review cues are not verified vulnerabilities.

## Run

Python 3.12+ is required. JSON uses the standard library. YAML input uses optional PyYAML; if unavailable, the CLI reports that blocker rather than substituting a parser.

```bash
PYTHONPATH=. python3.12 -m apishield.cli /path/to/authorized-openapi.json > report.json
python3.12 -m unittest discover -s tests -v
```

Input is capped at 4 MiB and 2,000 paths/10,000 operations. YAML aliases and duplicate keys are rejected. External `$ref` values are never fetched; unresolved references are listed in `issues`. The report contains input SHA-256 and JSON pointers to the declared configuration. The generated matrix lists cases an authorized analyst could later test; it does not execute them.

The implementation follows the [OpenAPI 3.1 security requirement rules](https://spec.openapis.org/oas/v3.1.0), including operation overrides and explicit anonymous alternatives. Its review references use the [OWASP API Security Top 10 (2023)](https://api-security.owasp.org/editions/2023/en/0x11-t10/) as a taxonomy, not as proof that a described API is vulnerable.

## Status and next milestone

The offline analyzer, CLI, and isolated unit tests work. There is no active test runner, authenticated service, database, or dashboard yet. The next milestone is a reviewed assessment workspace with explicit owner/scope records and a separately authorized, non-destructive test plan. See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and [VALIDATION_REPORT.md](VALIDATION_REPORT.md).
