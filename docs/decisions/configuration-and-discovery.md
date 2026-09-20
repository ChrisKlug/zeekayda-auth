# Configuration and discovery

The shape of `AuthorizationServerOptions`, how it is validated, and how it becomes the discovery
document. Issuer and endpoint-URI rules are `endpoints.md`. The full options reference is
`docs/reference/configuration.md`.

## Decisions in force

**Grouped nested options, and a group can never be nulled out.** Server-wide settings stay on the
root; per-endpoint and per-artifact settings live on `sealed`, get-only, eagerly-initialised nested
groups. `{ get; }` is what makes "assign `null` and drop the whole group's defaults" unrepresentable.
A flat class does not survive the ~70 metadata fields the full OIDC + RFC 8414 surface reaches:
IntelliSense collapses and cross-endpoint invariants have nowhere to live.

**The grouping rule is mechanical and spec-driven.** A property groups with any other whose
discovery key shares a spec-defined prefix — an endpoint name (`token_endpoint_*`), an artifact name
(`id_token_*`), a response shape (`response_*`). Groups named after an HTTP endpoint carry an
`Endpoint` suffix; groups that do not (`IdToken`, `Response`) do not. No shared prefix means the
root. Endpoint affinity is a permitted secondary criterion only when the *spec text itself* names a
property as a modifier of that endpoint — that is how RFC 7636's `code_challenge_*` parameters land
on `AuthorizationEndpoint` with nothing to form a prefix group with. It is never a judgement call.
`JwksEndpoint` exists holding only `Uri`, for the policy fields it will plausibly grow.

**Framework-behavior groups are a second, explicit category.** `SecurityHeaders` and `Logging` govern
the framework's own runtime behaviour and have no discovery-document counterpart at all. They are
permitted outside the prefix rule provided the name is plain descriptive English and never carries an
`Endpoint` suffix.

**The grouping rule places discovery-shaped configuration only.** A feature-registration hatch or
safety gate that is inert unless some other opt-in was also registered is not metadata, and this rule
does not license hoisting it onto the shared root. It co-locates with the feature that introduced it,
usually as a parameter on the registration method rather than a bindable option.

**Options carry data; the builder carries registrations.** `ZeeKayDaAuthBuilder` is the
service-registration surface — stores, signing providers, hashers, authenticators — and options data
never migrates onto it. Per-endpoint *behaviour* customisation goes through narrow, DI-resolved,
single-purpose interfaces. Builder-extension configuration methods were rejected: they split
configuration across two surfaces, do not bind from `IConfiguration`, break
`IOptionsSnapshot`/`IPostConfigureOptions` composition, and are invisible to a single validator.

**One root-rooted validator, not one per group.** Real rules are cross-group — `client_credentials`
in `GrantTypesSupported` requires at least one non-`none` entry in `TokenEndpoint.AuthMethodsSupported`
— so `IValidateOptions<AuthorizationServerOptions>` stays single and grows. It is a pure read-only
check: CORS-origin canonicalisation runs earlier in an `IPostConfigureOptions<T>`, which also freezes
the collection to read-only so nothing mutates it after validation.

**One CORS allowlist, on the root, for every endpoint a browser script calls.** `CorsOrigins` governs
discovery, JWKS and userinfo alike; none uses a cookie, so who may read one does not vary by endpoint.

**A host that supports no grant using the authorization endpoint serves neither the endpoint nor the
metadata describing it.** Without `authorization_code` nobody signs in, so `/connect/authorize` and
`/connect/endsession` are unmapped and the document omits `authorization_endpoint` (RFC 8414 §2),
`end_session_endpoint`, `response_modes_supported` and `code_challenge_methods_supported` (optional), and
`response_types_supported`. That last omission is a decided deviation: RFC 8414 §2 and OpenID Connect
Discovery §3 both mark it REQUIRED, and both, in §3.2 and §4.2, say a claim with zero elements MUST be
omitted — no document for such a host satisfies both sentences, and the MUST is followed. The document is
still served, at both discovery paths, because resource servers find `jwks_uri` through it — most look
under the OpenID Connect path even when the host is not an OP.

**One discovery document, two addresses.** The same document is served at OpenID Connect Discovery's
`/.well-known/openid-configuration` and at RFC 8414's `/.well-known/oauth-authorization-server`, on
every host. RFC 8414 §7.1.2 registers the OpenID Connect fields as OAuth metadata, so the superset is
valid at the OAuth address. A second, OAuth-only document was rejected: it doubles the public wire
model and provider surface for no client that needs the smaller shape, and it can still be added
later without breaking a host or a custom provider.

**`IValidateOptions<T>` plus `ValidateOnStart()` is the primary validation mechanism.** A check leaves
it only for one of three reasons: it needs async I/O, it needs a DI scope, or its whole purpose is a
side effect such as emitting a warning. Those become `IStartupVerifier`s (see
`startup-verification.md`); everything decidable synchronously from options values stays here.

**Closed protocol vocabularies are enums; genuinely open ones are ordinal strings.**
`GrantType`, `ResponseType`, `ResponseMode`, `PromptValue`, `CodeChallengeMethod` and
`SigningAlgorithm` are enums, because a new member needs framework code behind it anyway.
`TokenEndpoint.AuthMethodsSupported` is `ICollection<string>` because `IClientAuthenticator` is a real
extension point and a custom `tls_client_auth` must be expressible without a framework release —
strings carry that vocabulary end to end, and the option is the operator's global allowlist and the
only source discovery reads from.

**`GrantType` has no `implicit` or `password` member, `CodeChallengeMethod` no `plain` and `ResponseMode`
no `form_post` — not even `[Obsolete]` ones.** OAuth 2.1 removes the first two, RFC 9700 §2.1.1 prohibits
the third, and the authorization endpoint cannot answer with the fourth. `[Obsolete]` is a warning, not an
error: a host suppressing warnings could still configure and advertise a control with nothing behind it,
and "migrate off this" is the wrong message for something that never worked here. The type system makes
the state unrepresentable, so no validator rule compensates for it.

**A control is advertised only while it is enforced, and the code grant is not served without
it.** `CodeChallengeMethodsSupported` defaults to `[S256]` now that the token endpoint verifies
every `code_verifier` with it; it defaulted to `null`, omitting the field, for as long as
advertisement shipped ahead of verification, because a PKCE-aware client trusting the claim would
have been exposed to the interception attack PKCE prevents. Startup now fails when
`GrantTypesSupported` contains the code grant and the collection lacks `S256`, so the grant cannot
be served with the enforcement path unadvertised. `null` remains the omit state, valid only on a
host without the grant; an empty collection is a validation error.

**Configuration is never serialised to the wire.** `IDiscoveryDocumentProvider` maps
`AuthorizationServerOptions` onto `OpenIdConfigurationDocument`, the OIDC Discovery 1.0 wire model, so
an internal, freely-refactorable options class is never coupled to a spec-mandated contract. The
provider is public and replaceable — that is the escape hatch for a host that must advertise something
the framework does not model.

**The advertised signing algorithms are derived from the key set, never configured beside it.**
`id_token_signing_alg_values_supported` is the distinct algorithms of the published key set — every
configured slot, ascending by `SigningAlgorithm` value — read from the ring on each request.
Deriving from the *published* set rather than the producible one is what keeps the document stable
across a rotation: a `Previous` key's algorithm stays advertised for as long as that key is
published and tokens signed under it are still live.
`IdToken.AdvertisedSigningAlgorithms` narrows that set and can never widen it; a filter excluding the
signing key's own algorithm fails startup rather than advertising nothing usable. The cross-check
that asserted equality between a configured list and what the provider could produce is gone with the
contract it read (#511, #515) — the disagreement is unrepresentable rather than detected. A host
serving the protocol endpoints must therefore register a signing key source: with no key set there is
nothing to derive from, and startup fails with `signing.key_ring.missing` rather than the first
discovery request failing.

**A scope definition is three claim lists and an optional audience, and nothing else.**
`ScopeDefinition` names what the scope unlocks in the ID token, at userinfo and in the access token,
as OpenID Connect wire names, and may name the absolute URI of the resource server it is for. There
is no identity-resource, API-resource or API-scope registry: two scopes with the same audience string
are the same API. `StandardScopes` is a static template the host passes to `AddInMemoryScopes`, with
the §5.4 claims in both the ID-token and the userinfo list; scopes come from `IScopeRepository`, which
is what a tenant will resolve when the framework becomes tenant-aware. Startup fails when an audience
is not an absolute URI without a fragment (RFC 8707 §2, `scopes.audience.invalid`), when a scope
lists a protocol claim other than `sub` that selection would never deliver (`scopes.claims.reserved`),
and when an in-memory client allows a scope no definition exists for (`client.allowed_scopes.undefined`);
the authorization endpoint applies the last rule per request, which covers custom repositories.
`claims_supported` is derived from the discoverable scopes' claim lists plus the ID token's own
protocol claims, never configured, and is omitted by a host without the code grant.

**Collection keys bind by replacement, not merge.** An operator who sets one entry of an
`IConfiguration` collection key loses the rest of that key's defaults. The validator's
empty-and-subset checks are what turn the resulting gap into a startup failure rather than a quietly
narrowed server.

## Tried, didn't work

- **A CORS allowlist per endpoint.** Two shipped and were signed off, then collapsed into one root list
  when userinfo would have been the third; the knob had no security behind it.

- **A closed `TokenEndpointAuthMethod` enum for the advertised auth-method set.** Shipped alongside
  the per-client string set, then removed: with the enum as discovery's source, the document could
  not advertise a custom method a host had added through `IClientAuthenticator`, so the two halves of
  one vocabulary disagreed. Strings now carry it end to end.
- **Statically configured advertised signing algorithms.** `IdToken.SigningAlgValuesSupported` was an
  operator-declared list, on the reasoning that deriving from key state would make the document
  flicker during rotation. It made the two sources of truth disagreeable instead, which is what the
  deleted cross-check existed to catch; deriving from the published set — which a rotation grows
  before it shrinks — has the stability the static list was chosen for.
- **A flat options class.** The shipped shape before grouping. Reversed pre-1.0, moving every
  consumer's property paths and `IConfiguration` keys in one break.
