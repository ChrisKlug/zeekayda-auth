# ADR 0003 — `CodeChallengeMethod`: Enum Type, Default Value, and Discovery Placement for `code_challenge_methods_supported`

**Status:** Accepted  
**Date:** 2026-06-14

> **Amended by ADR 0007 §1a (2026-06-08):** the `TokenEndpointAuthMethod` enum is removed and is therefore no longer used as the example of the "use enums for closed protocol vocabularies" pattern — that vocabulary has been reclassified as an open extension point. Custom token endpoint auth methods are advertised by explicitly adding their string value to `TokenEndpoint.AuthMethodsSupported` and registering a covering `IClientAuthenticator`. The enum/string trade-off this ADR describes still applies to `CodeChallengeMethod`, `SigningAlgorithm`, `ResponseType`, `ResponseMode`, `GrantType`, and `PromptValue`. The discussion below is preserved as historical record.

> **Amended by issue #209 (2026-06-17):** A new placement rule is added: protocol-vocabulary
> enum types whose consumers are exclusively within a specific feature domain belong in that
> domain's namespace, not the root `ZeeKayDa.Auth` namespace. `SigningAlgorithm` is the
> canonical example — it was moved from `ZeeKayDa.Auth` to `ZeeKayDa.Auth.Tokens`.
> See [issue #209](https://github.com/zeekayda/zeekayda-auth/issues/209) for the full
> rationale.

---

## Context

The OIDC Discovery 1.0 / RFC 8414 §2 `code_challenge_methods_supported` metadata field advertises
which PKCE challenge methods the authorisation server accepts. PKCE is defined in
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) and is made mandatory for all clients — public
and confidential alike — by [OAuth 2.1 (draft)](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/).

[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) §2.1.1 (OAuth 2.0 Security Best Current
Practice) goes further: it explicitly deprecates the `plain` challenge method ("The plain code
challenge method... MUST NOT be used") and requires `S256` for all new deployments.

A GitHub issue proposed representing this field as `ICollection<string>?` on
`AuthorizationServerOptions`. The repository owner raised two design questions:

1. Should the type be `string` or a typed enum, consistent with the existing
   `SigningAlgorithm`, `ResponseType`, `ResponseMode`, `GrantType`, and `TokenEndpointAuthMethod`
   patterns?
2. What should the default value be?

Three further questions flow from those two:

3. Where in the grouped nested options shape (ADR 0002) should the property live?
4. Does the `AuthorizationServerOptionsValidator` still need a "reject `plain`" rule?
5. Are there additional design concerns to resolve before implementation begins?

---

## Decision

### 1. Type: a new `CodeChallengeMethod` enum — not `string`

`CodeChallengeMethod` is introduced as a new public enum in `ZeeKayDa.Auth`, following the exact
pattern of every other protocol-string field in the codebase:

```csharp
[JsonConverter(typeof(JsonStringEnumConverter<CodeChallengeMethod>))]
public enum CodeChallengeMethod
{
    /// <summary>
    /// SHA-256 code challenge method (<c>S256</c>).
    /// The only method permitted by
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>.
    /// </summary>
    [JsonStringEnumMemberName("S256")]
    S256,
}
```

The enum starts with a single member. Future methods (`S384`, `S512`, or any that a future RFC
standardises) are added **only when the framework also implements the corresponding verifier
logic** at the token endpoint. This is the same lifecycle rule implied by every other enum in the
codebase: advertise what you enforce.

### 2. `plain` is excluded entirely — not included as `[Obsolete]`

RFC 9700 §2.1.1 prohibits `plain` outright. The framework has no implementation of `plain`
challenge verification and will not have one. The enum therefore contains no `Plain` member —
not even an `[Obsolete]`-annotated one. See the Rejected Alternatives section for why the
`[Obsolete]` approach is insufficient.

### 3. Property location: `AuthorizationEndpointOptions.CodeChallengeMethodsSupported`

Under ADR 0002's grouping rules, `code_challenge_methods_supported` belongs in
`AuthorizationEndpointOptions`.

The primary prefix rule from ADR 0002 §1 does not produce a group for this field in isolation —
it is the only discovery metadata key with the `code_challenge_` prefix. Alone, that would place
it on the root alongside `GrantTypesSupported`.

However, ADR 0002 §1 explicitly permits **endpoint-affinity as a secondary criterion**:

> "A property may join a group whose name is the endpoint it spec-modifies, even when the
> property's own discovery key does not share that endpoint's prefix. The criterion is still
> mechanical (the spec text itself must identify the property as an authorization/token/etc.
> endpoint modifier — not a judgement call by the implementer)."

RFC 7636 §4.3 is unambiguous: `code_challenge` and `code_challenge_method` are parameters of the
**authorisation request** sent to the authorisation endpoint. The discovery field exists to tell
clients whether the authorisation endpoint will accept and verify those parameters. The spec
text itself identifies `code_challenge_methods_supported` as a modifier of authorisation-endpoint
behaviour — which is precisely the secondary criterion ADR 0002 establishes. The property
therefore belongs in `AuthorizationEndpointOptions`, not on the root.

This placement is also correct for forward-compatibility: when PKCE enforcement is implemented,
the enforcement policy will live inside the authorisation-endpoint handler. Having the
advertisement and the enforcement configuration share a group eliminates a class of "I configured
the wrong endpoint group" mistakes.

### 4. Default value: `null` (field omitted from the discovery document)

`AuthorizationEndpointOptions.CodeChallengeMethodsSupported` defaults to `null`.

When the property is `null`, the `code_challenge_methods_supported` field is absent from the
serialised discovery document — consistent with how all optional discovery fields are handled
via `[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]` on the wire model.

Consumers explicitly opt in by assigning `[CodeChallengeMethod.S256]` once PKCE challenge
verification is enforced at the token endpoint. See Rejected Alternatives for why a default of
`[S256]` was rejected.

### 5. Validator: no "reject `plain`" rule; one null-or-empty guard added

Because `plain` is not a member of `CodeChallengeMethod`, it is impossible to configure —
the type system makes the "reject `plain`" validator rule structurally unnecessary.

One new rule is added to `AuthorizationServerOptionsValidator` in
`ZeeKayDa.Auth/Configuration/`:

```
If AuthorizationEndpoint.CodeChallengeMethodsSupported is non-null, it must contain at least
one value. An empty collection is a configuration error: it would publish
"code_challenge_methods_supported": [] in the discovery document — advertising PKCE support
with no usable method, which is never a valid server state.
```

The validator rule text:

```
AuthorizationServerOptions.AuthorizationEndpoint.CodeChallengeMethodsSupported must not be an
empty collection. Either set it to null to omit the field from the discovery document, or
provide at least one value (e.g. CodeChallengeMethod.S256). See RFC 7636 §4.3 and RFC 8414 §2.
```

---

## Full implementation surface

The following describes exactly what the developer must add or modify. No other files are
affected by this ADR.

### New file: `src/ZeeKayDa.Auth/CodeChallengeMethod.cs`

```csharp
using System.Text.Json.Serialization;

namespace ZeeKayDa.Auth;

/// <summary>
/// PKCE code challenge method values that can be advertised in the discovery document, as
/// defined in <see href="https://www.rfc-editor.org/rfc/rfc7636">RFC 7636 (PKCE)</see>.
/// </summary>
/// <remarks>
/// <para>
/// The <c>plain</c> method is intentionally absent.
/// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>
/// (OAuth 2.0 Security Best Current Practice) explicitly prohibits its use: "The plain code
/// challenge method... MUST NOT be used."
/// </para>
/// <para>
/// New methods are added to this enum only when the framework implements the corresponding
/// verifier at the token endpoint. Do not advertise a method the server cannot verify.
/// </para>
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<CodeChallengeMethod>))]
public enum CodeChallengeMethod
{
    /// <summary>
    /// SHA-256 code challenge method (<c>S256</c>).
    /// Required by
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>
    /// for all new deployments.
    /// </summary>
    [JsonStringEnumMemberName("S256")]
    S256,
}
```

### Modified: `src/ZeeKayDa.Auth/AuthorizationEndpointOptions.cs`

Add one property:

```csharp
/// <summary>
/// Gets or sets the PKCE code challenge methods supported by this authorization server.
/// When <see langword="null"/> (the default), the <c>code_challenge_methods_supported</c>
/// field is omitted from the discovery document.
/// </summary>
/// <remarks>
/// <para>
/// Set to <c>[<see cref="CodeChallengeMethod.S256"/>]</c> once PKCE challenge verification
/// is enforced at the token endpoint. Advertising methods the server does not actually verify
/// gives clients a false assurance — do not set this property until enforcement is in place.
/// </para>
/// <para>
/// Maps to the <c>code_challenge_methods_supported</c> discovery metadata field defined in
/// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-2">RFC 8414 §2</see>.
/// </para>
/// </remarks>
public ICollection<CodeChallengeMethod>? CodeChallengeMethodsSupported { get; set; }
```

### Modified: `src/ZeeKayDa.Auth/Discovery/OpenIdConfigurationDocument.cs`

Add one property to the wire-format record:

```csharp
/// <summary>
/// Gets the PKCE code challenge methods supported by this authorization server.
/// Absent from the document when <see langword="null"/>.
/// </summary>
[JsonPropertyName("code_challenge_methods_supported")]
[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
public IReadOnlyCollection<CodeChallengeMethod>? CodeChallengeMethodsSupported { get; init; }
```

The property is **not** `required` — per the spec the field is optional and the record must
remain constructable without it.

### Modified: `src/ZeeKayDa.Auth/Discovery/DiscoveryDocumentProvider.cs`

Add one line to the object initialiser in `GetDocumentAsync`:

```csharp
CodeChallengeMethodsSupported = options.AuthorizationEndpoint.CodeChallengeMethodsSupported is { } methods
    ? [.. methods]
    : null,
```

The conditional copy-to-array is intentional: it ensures the wire model holds a stable
`IReadOnlyCollection<CodeChallengeMethod>` snapshot of the option value at the time the
document is built, matching the defensive copy pattern already applied to all other collection
fields in the same initialiser.

### Modified: `src/ZeeKayDa.Auth/Configuration/AuthorizationServerOptionsValidator.cs`

Add one validation block in the `Validate` method, adjacent to the existing
`AuthorizationEndpoint.Uri` validation:

```csharp
if (options.AuthorizationEndpoint.CodeChallengeMethodsSupported is { Count: 0 })
{
    return ValidateOptionsResult.Fail(
        "AuthorizationServerOptions.AuthorizationEndpoint.CodeChallengeMethodsSupported " +
        "must not be an empty collection. Either set it to null to omit the field from the " +
        "discovery document, or provide at least one value (e.g. CodeChallengeMethod.S256). " +
        "See RFC 7636 §4.3 and RFC 8414 §2.");
}
```

The pattern `is { Count: 0 }` is deliberate: it matches only a non-null, empty collection —
not `null`, which is the valid "omit the field" state.

---

## Rejected Alternatives

### Option A — `ICollection<string>?`

**Rejected.** Using `string` is inconsistent with the five existing enum-typed protocol-string
fields (`SigningAlgorithm`, `ResponseType`, `ResponseMode`, `GrantType`,
`TokenEndpointAuthMethod`). A `string` property gives consumers no compile-time guidance about
valid values. It accepts `"plain"`, which RFC 9700 prohibits, forcing a validator rule to
compensate for what the type system should prevent. It accepts arbitrary unknown strings that
no client library will recognise, silently producing a malformed discovery document.

The sole argument in favour — "open to future extension without an enum change" — does not hold
under inspection. Future PKCE methods still require a framework implementation before they can
be advertised honestly (§5 of the decision above). That implementation work triggers a new
framework release regardless; updating the enum in the same release costs nothing extra. A new
`[JsonStringEnumMemberName("S384")] S384` member is a non-breaking minor-version addition.

### `[Obsolete] Plain` member

**Rejected.** An `[Obsolete]` attribute produces a compiler warning, not a compile error. A
consumer who uses `#pragma warning disable CS0618`, suppresses Roslyn warnings globally, or is
not paying attention to warnings could configure `Plain` and advertise it in the discovery
document. The server would then receive `code_challenge_method=plain` from PKCE-aware clients.
Without a verifier implementation, the server would either reject valid authorisation-code
exchanges (if the token endpoint validates the `code_verifier` parameter and finds no handler)
or silently accept PKCE-bypass attempts (if no validation exists at all). Neither outcome is
acceptable. The `[Obsolete]` pattern is appropriate for features that **once existed and need a
migration path** — `plain` has never been implemented in this framework, so there is nothing to
migrate from and no legitimate use case the flag would serve.

### Default `[CodeChallengeMethod.S256]`

**Rejected.** Defaulting to `[S256]` tells every relying party, from the moment `AddZeeKayDaAuth`
is first called, that the server enforces PKCE challenge verification. It does not. A PKCE-aware
client will include `code_challenge=<value>&code_challenge_method=S256` in every authorisation
request and present a `code_verifier` at the token endpoint. If the token endpoint ignores
`code_verifier` — because enforcement is not yet implemented — the client has been given a false
security assurance. An authorisation-code interception attack (the scenario PKCE was designed to
prevent) would succeed silently.

The framework's design principle is "Secure by default". The secure default for an unimplemented
security control is to not advertise it — not to advertise it and hope enforcement catches up.
The correct progression is:

1. `null` default (today — no enforcement, no advertisement).
2. Consumer sets `[CodeChallengeMethod.S256]` once PKCE enforcement is implemented at the token
   endpoint.
3. A future ADR may make `[CodeChallengeMethod.S256]` the enforced default when both advertisement
   and enforcement are considered complete.

### Root-level `AuthorizationServerOptions.CodeChallengeMethodsSupported`

**Rejected.** A strict reading of ADR 0002's prefix rule would place this property on the root
because `code_challenge_methods_supported` is the only discovery key with that prefix — there
are no peers to form a group from. However, ADR 0002 §1 explicitly acknowledges and codifies
endpoint-affinity as a permitted secondary criterion, and uses the `request_*` family under
`AuthorizationEndpoint` as a direct precedent. RFC 7636 §4.3 unambiguously defines
`code_challenge` and `code_challenge_method` as authorisation-request parameters — the spec
text itself identifies this as an authorisation-endpoint modifier. Placing the advertisement
configuration on the root while authorisation-endpoint behaviour is concentrated in
`AuthorizationEndpointOptions` would be misleading to consumers and would split conceptually
related settings across the options hierarchy without a principled reason.

---

## Consequences

### Positive

- **Type safety eliminates the "reject `plain`" validator rule.** The configuration is
  impossible to express; no compensating validation is required.
- **Consistent with all existing enum-typed fields.** No new patterns are introduced.
  Contributors familiar with `SigningAlgorithm` or `GrantType` will know exactly how to work
  with `CodeChallengeMethod`.
- **Honest default.** The discovery document does not claim PKCE enforcement until the token
  endpoint enforces it. Relying parties that read the discovery document get accurate
  information.
- **Empty-collection guard provides an early warning** for the common mistake of assigning
  `CodeChallengeMethodsSupported = []` instead of `null`.
- **Forward-compatible.** Adding `S384` or `S512` in a future release requires only: (1)
  implement the verifier, (2) add the enum member with its `[JsonStringEnumMemberName]`
  annotation, (3) ship a minor-version bump. The addition is non-breaking: existing consumers
  who have set `[CodeChallengeMethod.S256]` continue to work unchanged.
- **Correct group placement.** Advertising and enforcement configuration share a group,
  reducing the risk of "I configured the wrong part of the options tree" mistakes when
  enforcement lands.

### Negative / Trade-offs

- **Closed enum limits consumer extensibility.** A consumer operating a custom PKCE
  implementation that uses a non-standard or experimental challenge method (e.g. one under an
  active IETF draft) cannot advertise it through `CodeChallengeMethodsSupported` without a
  framework release. This is intentional: advertising an unimplemented or unverified security
  control is worse than not advertising it. Consumers in this position should override the
  discovery document via `IDiscoveryDocumentProvider`.
- **Enum update required for new IETF methods.** If a future RFC standardises `S384` or `S512`
  (currently not standardised for PKCE), a framework release is needed before consumers can
  advertise it. This is the correct ordering: implement then advertise. The cost of the enum
  update is negligible compared to implementing the verifier.
- **No enforcement today.** Shipping the advertisement capability (`CodeChallengeMethodsSupported`)
  without the enforcement capability (token endpoint `code_verifier` validation) creates a
  discoverable gap. The `null` default and the XML documentation comment on the property are the
  primary safeguards — they are explicit and visible in IntelliSense. A future ADR will address
  the enforcement side when it is implemented.
