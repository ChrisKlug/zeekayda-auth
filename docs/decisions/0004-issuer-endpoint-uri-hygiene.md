# ADR 0004 — Issuer and Endpoint URI Hygiene

**Status:** Accepted  
**Date:** 2026-06-04

---

## Context

Issue #42 identified four related hygiene gaps:

1. Endpoint URI overrides could silently point to a different authority than `Issuer`.
2. Non-canonical issuer forms (uppercase scheme/host, explicit default port) were accepted.
3. ZeeKayDa.Auth endpoints could be served over HTTP on non-loopback hosts at request time.
4. `MapZeeKayDaAuth()` could throw a different error shape than startup validation for invalid issuers.

These gaps affect OIDC/OAuth metadata integrity and transport-security posture.

---

## Decision

1. **Issuer/endpoint authority binding is mandatory.**  
   `AuthorizationEndpoint.Uri`, `TokenEndpoint.Uri`, and `JwksEndpoint.Uri` must use the same
   authority as `Issuer`. Cross-authority overrides are rejected at startup.

2. **Issuer must be canonical.**  
   Startup validation rejects issuer values that are not canonical:
   - scheme must be lowercase
   - host must be lowercase
   - default ports must be omitted (`:443` for HTTPS, `:80` for HTTP loopback)

   Validation errors include the canonical replacement value.

3. **Request-time HTTPS guard is enforced.**  
   All ZeeKayDa.Auth protocol endpoints reject non-HTTPS, non-loopback requests with
   `421 Misdirected Request`.  
   `AllowInsecureIssuer = true` remains loopback-only and development-only.

4. **Map-time and startup-time issuer errors are unified.**  
   `MapZeeKayDaAuth()` now eagerly evaluates `IOptions<AuthorizationServerOptions>.Value` so
   invalid issuer configuration fails with the same `OptionsValidationException` contract as
   `ValidateOnStart()`.

---

## Consequences

### Positive

- Stronger issuer/metadata integrity and safer defaults.
- Clearer diagnostics with canonical rewrite guidance.
- Consistent operator experience across startup and map-time failure paths.

### Trade-offs

- Existing configurations with cross-authority endpoint overrides now fail startup.
- Existing non-canonical issuer values now fail startup and must be corrected.

Cross-authority overrides may be reconsidered in a future low-priority issue once there is a
concrete deployment need and a complete threat model.
