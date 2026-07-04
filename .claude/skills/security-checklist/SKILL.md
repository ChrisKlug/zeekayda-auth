---
name: security-checklist
description: Security review checklist for ZeeKayDa.Auth. Apply to every change touching tokens, cryptography, endpoints, or storage — during security review, and as a developer self-check before opening a PR that touches those areas.
---

# Security Checklist

Apply this checklist to **every auth-related change**. It is the shared reference for the security agent's reviews and the developer's pre-PR self-check.

## Token Security
- [ ] Tokens are not logged or exposed in error messages
- [ ] Access tokens have appropriate short lifetimes
- [ ] Refresh token rotation is implemented (RFC 6749 §10.4)
- [ ] Token binding is considered where applicable

## Cryptography
- [ ] No custom cryptography — only well-established .NET cryptographic primitives
- [ ] RSA keys are at least 2048-bit; EC keys are P-256 or better
- [ ] Nonces are cryptographically random (not `Random`, use `RandomNumberGenerator`)
- [ ] Constant-time comparison for secrets (no timing oracles)
- [ ] PKCE code verifier/challenge validation is correct and mandatory

## Endpoint Security
- [ ] PKCE is enforced for all public clients (RFC 7636)
- [ ] `state` parameter validated to prevent CSRF
- [ ] Redirect URI validation is exact-match (no wildcard, no open redirect)
- [ ] `iss` claim validated in token responses (RFC 9207)
- [ ] Mix-up attack mitigations in place

## Input Validation
- [ ] All inputs are validated before use in cryptographic operations
- [ ] Scope values are validated against an allowlist
- [ ] No SQL injection or path traversal vectors in storage adapters

## Key References

- OAuth 2.0 Security Best Current Practice (RFC 9700): https://www.rfc-editor.org/rfc/rfc9700
- OAuth 2.1 *(draft)*: https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/ — mandates PKCE for all clients and removes the implicit and ROPC flows. Treat any implementation of those removed flows as a security concern requiring explicit justification.
- OAuth 2.0 Threat Model (RFC 6819): https://www.rfc-editor.org/rfc/rfc6819
- PKCE (RFC 7636): https://www.rfc-editor.org/rfc/rfc7636
- OpenID Connect Core security considerations: https://openid.net/specs/openid-connect-core-1_0.html#Security
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
