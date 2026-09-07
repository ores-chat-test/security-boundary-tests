# security-boundary-tests

Status: **contract-only**. This suite specifies negative authorization, input limits, origin policy, credential separation, and safe failures.

This repository is an executable acceptance-suite boundary, not evidence that the corresponding product capability is complete. The suite must target both `ores-chat` and the isolated `ores-chat-test` fixture. Promotion to `live` requires hosted execution, deterministic assertions, and redacted retained evidence.

The machine-readable plan is in `suite.json` and is validated by the organization policy action pinned to an immutable commit. Public, customer, administrator, and internal-service identities are never interchangeable.

## Shared-stack boundary model

`shared-stack-boundary/validate.mjs` executes the adversarial cases in `shared-stack-boundary/cases.json`. The model fixes the expected integration order and failure behavior across `ores-middleware`, `shared-auth`, `ores-rate-limit`, `ores-redis-lru-cache`, and `ores-otel`:

1. production startup rejects test bypass and fault injection;
2. forwarded identity is honored only for configured trusted peers;
3. authentication, realm matching, and administrator assurance precede rate limiting;
4. only versioned opaque rate-limit keys are accepted;
5. the local LRU may cache active denials only, never permits;
6. strict enforcement fails closed when Redis is unavailable;
7. Redis denials remain authoritative;
8. telemetry retains approved key names only and never exposes credentials, claims, prompts, documents, signatures, database locations, or raw client identity.

The current cases are deterministic and synthetic. They prove the contract and CI wiring, not that a deployed service has adopted it. Live promotion requires the same assertions against both the production integration and isolated test deployment, with private redacted receipts.
