# ADR 0004 — Issuer and Endpoint URI Hygiene

Status: Accepted   ·   Date: 2026-06-04   ·   Issue: #42

## Decision

1. **Issuer/endpoint authority binding is mandatory.** `AuthorizationEndpoint.Uri`,
   `TokenEndpoint.Uri`, and `JwksEndpoint.Uri` must use the same authority as `Issuer`;
   cross-authority overrides are rejected at startup.
2. **Issuer must be canonical.** Startup validation rejects non-canonical issuer values —
   uppercase scheme or host, or an explicit default port (`:443` HTTPS, `:80` HTTP loopback).
   Validation errors include the canonical replacement value.
3. **Request-time HTTPS guard.** All ZeeKayDa.Auth protocol endpoints reject non-HTTPS,
   non-loopback requests with `421 Misdirected Request`. `AllowInsecureIssuer = true` remains
   loopback-only and development-only.
4. **Map-time and startup-time issuer errors are unified.** `MapZeeKayDaAuth()` eagerly evaluates
   `IOptions<AuthorizationServerOptions>.Value`, so invalid issuer configuration fails with the
   same `OptionsValidationException` contract at map time as at `ValidateOnStart()`.

## Why

Four related hygiene gaps prompted this: endpoint overrides could silently point at a different
authority than `Issuer`; non-canonical issuer forms were accepted; endpoints could be served over
HTTP on non-loopback hosts at request time; and `MapZeeKayDaAuth()` could throw a different error
shape than startup validation for the same invalid issuer. All four affect OIDC/OAuth metadata
integrity or transport-security posture, so closing them together avoids a second stop-the-world
pass through the same validation code.

Cross-authority overrides could be reconsidered later given a concrete deployment need and a
complete threat model, but no such need exists today, so they stay rejected outright rather than
gated behind an opt-in.

## Consequences

Stronger issuer/metadata integrity, clearer diagnostics (canonical rewrite guidance included in
errors), and a consistent operator experience across startup and map-time failures. Existing
configurations with cross-authority overrides or non-canonical issuer values now fail startup and
must be corrected.
