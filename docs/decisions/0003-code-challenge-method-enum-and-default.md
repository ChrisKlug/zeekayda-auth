# ADR 0003 — `CodeChallengeMethod`: Enum Type, Default, and Placement

Status: Accepted   ·   Date: 2026-06-14   ·   Issue: #209

## Decision

`CodeChallengeMethod` is a new public enum in `ZeeKayDa.Auth`, following the existing
enum-typed-protocol-field pattern (`SigningAlgorithm`, `ResponseType`, `ResponseMode`,
`GrantType`). It starts with a single member, `S256`. `plain` has no member at all — not even an
`[Obsolete]` one — since [RFC 9700 §2.1.1](https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1)
prohibits it outright and the framework has, and will have, no verifier for it. Future methods
(`S384`, `S512`, …) are added only once the framework implements the corresponding verifier.

The property — `AuthorizationEndpointOptions.CodeChallengeMethodsSupported` — lives under
`AuthorizationEndpoint`, not on the options root, and defaults to `null` (field omitted from the
discovery document). The validator adds one rule: the collection, if non-null, must not be empty
(`is { Count: 0 }` is rejected; `null` is the valid "omit" state). No "reject `plain`" validator
rule exists — the type system makes that state unrepresentable.

*Amended by ADR 0007:* `TokenEndpointAuthMethod` (previously the fifth example of this same
enum-typed-protocol-field pattern) was removed and replaced with an open, string-based vocabulary;
the enum/string trade-off discussed here still applies to `CodeChallengeMethod`, `SigningAlgorithm`,
`ResponseType`, `ResponseMode`, `GrantType`, and `PromptValue`.

*Amended by issue #209:* a placement rule was added for protocol-vocabulary enums whose consumers
sit entirely within one feature domain — such an enum belongs in that domain's namespace, not the
root `ZeeKayDa.Auth` namespace. `SigningAlgorithm` moved from `ZeeKayDa.Auth` to
`ZeeKayDa.Auth.Tokens` under this rule.

## Why

- **Enum over `string`:** consistent with every other protocol-vocabulary field; a `string`
  property accepts `"plain"` (forcing a validator to compensate for what the type system should
  prevent) and arbitrary unrecognised values. "Open to future extension" doesn't hold up: any new
  method needs a framework-side verifier before it can be honestly advertised anyway, so updating
  an enum in the same release costs nothing extra.
- **No `[Obsolete] Plain` member:** `[Obsolete]` is a compiler warning, not an error — a consumer
  who suppresses warnings (or isn't watching them) could still configure and advertise `plain`
  with no verifier behind it, risking either broken code exchanges or a silent PKCE bypass.
  `[Obsolete]` also implies "this used to work, migrate off it" — `plain` was never implemented
  here, so there's nothing to migrate from.
- **`null` default, not `[S256]`:** defaulting to advertising `S256` would tell every relying
  party the server enforces PKCE from the moment `AddZeeKayDaAuth` runs — false, until the token
  endpoint actually validates `code_verifier`. A PKCE-aware client trusting that claim would be
  exposed to exactly the authorization-code-interception attack PKCE exists to prevent. Secure
  default for an unimplemented control is "don't advertise it," not "advertise and hope
  enforcement catches up."
- **`AuthorizationEndpoint`, not root:** a strict prefix-count reading of ADR 0002 would put this
  alone on the root (no other `code_challenge_*` key exists to group with). But
  [RFC 7636 §4.3](https://www.rfc-editor.org/rfc/rfc7636#section-4.3) defines `code_challenge`/
  `code_challenge_method` as authorization-request parameters — the endpoint-affinity criterion
  ADR 0002 already permits — so it groups with `AuthorizationEndpoint` instead, keeping
  advertisement and future enforcement configuration together.

## Consequences

Advertisement (this ADR) ships ahead of enforcement (token-endpoint `code_verifier` validation,
addressed separately); the `null` default and the XML doc on the property are what keep that gap
from being silently misleading. A consumer needing a non-standard or experimental challenge method
cannot advertise it without a framework release — intentional, since advertising an unverified
security control is worse than not advertising it; such a consumer should override
`IDiscoveryDocumentProvider` instead. Adding `S384`/`S512` later is a non-breaking minor-version
enum addition once both are standardised and implemented.
