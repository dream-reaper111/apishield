# Security model

Only analyze specifications you are authorized to review. APIShield does not contact documented servers. It never sends credentials or requests to target APIs. OpenAPI text is untrusted; YAML aliases and duplicate keys are rejected and external references are not resolved. Protect reports because paths and security schemes may be sensitive.

The current offline CLI has no server credentials or persistent storage. `anonymous_access_specification_review` describes the document, not proven runtime exposure. `authorization_review_matrix` is a human test plan and must not be executed without explicit scope approval. No automated active BOLA test exists.
