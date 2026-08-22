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

**`GrantType` has no `implicit` and no `password` member, and `CodeChallengeMethod` has no `plain`
member — not even an `[Obsolete]` one.** OAuth 2.1 removes the first two; RFC 9700 §2.1.1 prohibits
the third outright and the framework has no verifier for it. `[Obsolete]` is a warning, not an error:
a host suppressing warnings could still configure and advertise a control with nothing behind it, and
"migrate off this" is the wrong message for something that never worked here. The type system makes
the state unrepresentable, so no validator rule compensates for it.

**Never advertise a control that is not yet enforced.** `CodeChallengeMethodsSupported` defaults to
`null`, meaning the field is omitted from discovery, precisely because advertisement shipped ahead of
`code_verifier` validation. Defaulting to `[S256]` would tell every relying party that PKCE is
enforced from the moment `AddZeeKayDaAuth` runs, and a PKCE-aware client trusting that claim would be
exposed to the exact interception attack PKCE exists to prevent. The secure default for an
unimplemented control is silence. `null` is the omit state; an empty collection is a validation error.

**Configuration is never serialised to the wire.** `IDiscoveryDocumentProvider` maps
`AuthorizationServerOptions` onto `OpenIdConfigurationDocument`, the OIDC Discovery 1.0 wire model, so
an internal, freely-refactorable options class is never coupled to a spec-mandated contract. The
provider is public and replaceable — that is the escape hatch for a host that must advertise something
the framework does not model.

**Discovery is a stable, cached contract, and advertised signing algorithms are statically
configured.** Deriving `id_token_signing_alg_values_supported` from whichever keys happen to be loaded
would make the document flicker during key rotation. Operators declare what the server supports;
key state does not.

**Collection keys bind by replacement, not merge.** An operator who sets one entry of an
`IConfiguration` collection key loses the rest of that key's defaults. The validator's
empty-and-subset checks are what turn the resulting gap into a startup failure rather than a quietly
narrowed server.

## Tried, didn't work

- **A closed `TokenEndpointAuthMethod` enum for the advertised auth-method set.** Shipped alongside
  the per-client string set, then removed: with the enum as discovery's source, the document could
  not advertise a custom method a host had added through `IClientAuthenticator`, so the two halves of
  one vocabulary disagreed. Strings now carry it end to end.
- **A flat options class.** The shipped shape before grouping. Reversed pre-1.0, moving every
  consumer's property paths and `IConfiguration` keys in one break.
