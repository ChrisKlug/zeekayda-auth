# ADR 0010 — Claims Storage Strategy for Authorization Code and Refresh Token Entries

**Status:** Proposed  
**Date:** 2026-06-20

**Amends ADR 0008 §2 and §3** — adds a `Claims` property to `AuthorizationCodeEntry` and
`RefreshTokenEntry`. See §4.

---

## Context

ADR 0008 defined the store contracts for authorization codes and refresh tokens. Both entry
records (`AuthorizationCodeEntry` and `RefreshTokenEntry`) carry `Sub` plus grant metadata —
scope, expiry, client ID, SSO session ID — but neither carries user claims. The question of
where claims come from when an access token is minted was not addressed, leaving the behaviour
determined by implementation convention rather than an explicit decision.

The gap matters for three reasons:

1. **Breaking-change timing.** If snapshotting is the correct answer, a `Claims` property must
   be added to both entry records before any implementing code merges. Adding it post-merge is a
   breaking change to a freshly-shipped public API. Issues #246 and #247 (the PR pair that
   defines the entry records and store interfaces) cannot merge until this decision is settled.

2. **Session consistency.** The behaviour of "re-fetch on every issuance" versus "snapshot at
   grant time" has direct, user-visible consequences: one model means a role revocation is
   reflected in the very next access token; the other means it is not visible until
   re-authentication. Both are valid industry choices but they must be explicit.

3. **Security model.** Stale claims in a long-lived session — particularly stale authorization
   claims like roles or group memberships — affect the blast radius of a compromised or
   mis-attributed account. The choice must be grounded in the relevant threat model
   (RFC 6819, RFC 9700).

### What the current codebase does (implicit)

Neither entry record has a `Claims` property. The token issuance pipeline — which does not exist
yet as implemented code — would implicitly need to load claims from the identity store at every
access token mint. That is the "re-fetch" model by default-of-omission. No claim transformation
hook exists to override this.

### Industry reference

Duende IdentityServer, Auth0, and Keycloak all re-fetch claims by default but expose a
transformation hook (IdentityServer's `IProfileService`, Auth0's Actions pipeline, Keycloak's
Protocol Mapper SPIs). The hook allows operators to snapshot, augment, or replace the re-fetched
claims. Without a hook, re-fetch and snapshot behave identically from the operator's perspective
— they have no way to intervene.

---

## Decision

### 1. Strategy: snapshot claims at grant time, carry them on the entry records

**Option B is chosen.** Claims are captured at authorisation time and stored on
`AuthorizationCodeEntry`. At auth code exchange they are written to `RefreshTokenEntry` verbatim.
All subsequent rotation cycles replay the stored snapshot; no identity store read occurs during
refresh exchanges.

The rationale follows from first principles, not industry fashion:

**The spec does not require re-fetch.** RFC 6749 and RFC 9700 define the *semantics* of access
tokens — the claims within them are application-defined. Neither RFC requires the authorization
server to consult the identity store at token-endpoint time. The spec's consistency requirement
is about *grant* consistency: the token endpoint must issue tokens consistent with the original
grant (same scope, same subject). Nothing in the spec requires that the *content* of the access
token be re-evaluated against the live identity store at every issuance.

**Re-fetch without a hook is strictly worse than snapshotting.** Without a claim transformation
pipeline (which does not exist yet in ZeeKayDa.Auth), re-fetch means the token endpoint silently
reads the identity store on every access token mint — including rotation — but operators cannot
observe or modify that read. This introduces a hidden I/O dependency on the hot path with no
extension point. In contrast, the snapshot model makes the dependency explicit: claims are loaded
once, at interaction time, where the host application is already calling the identity store as
part of authentication, and they are carried deterministically forward.

**Snapshotting produces a clear, testable data flow.** The claims in any access token are
exactly the claims on the `RefreshTokenEntry` that was consumed to produce it. No implicit
read occurs; the token endpoint is a pure function of its inputs. This makes the issuance
pipeline independently testable without a live identity store, consistent with the project's
testability principle (Design Principle §4).

**The stale-claims concern is addressed by access token lifetime, not by re-fetch.** The
canonical response to "a role was revoked but the user still has a valid access token" is to
shorten access token lifetimes (15 minutes is the common recommendation) and accept that the
revocation is visible on the next access token mint. This is the same answer regardless of
whether claims are re-fetched at rotation: a 15-minute access token minted from a re-fetched
rotation still gave the user 15 minutes of stale-role access. Re-fetch-on-rotation does not
materially reduce the blast radius unless rotation is continuous and access tokens are very
short-lived — an unusual operational profile. The right lever is access token lifetime, not
claims freshness on rotation.

**A future claim transformation pipeline can accommodate re-fetch semantics.** When
`IClaimsTransformer` or equivalent is added (see §6), an operator who *wants* re-fetch
behaviour can register a transformer that ignores the snapshot and calls the identity store.
The snapshotting default does not foreclose that option. The inverse is not true: a re-fetch
default with no hook cannot be overridden by an operator who wants consistent snapshots —
they would need to implement their own store.

### 2. No divergence between the two entry records

`AuthorizationCodeEntry` and `RefreshTokenEntry` use the same snapshot strategy. There is no
case for divergence in v1:

- A snapshot-on-auth-code / re-fetch-on-rotation hybrid would produce access tokens whose
  contents are unpredictable relative to the original grant: the first access token (minted at
  code exchange from the snapshot) would have different claims than subsequent ones (minted from
  re-fetch at rotation). This inconsistency would surprise clients and is not a meaningful
  security improvement.
- The `RefreshTokenEntry` is the authoritative record across the grant lifetime. Carrying the
  snapshot forward from `AuthorizationCodeEntry` to `RefreshTokenEntry` at code exchange is
  a simple assignment; requiring the token endpoint to go back to the identity store on
  every rotation undoes the entire benefit of the snapshot at no security gain.

### 3. .NET type for the `Claims` property

The `Claims` property on both records is typed as `IReadOnlyList<ClaimRecord>` where
`ClaimRecord` is a new `readonly record struct` in `ZeeKayDa.Auth.Stores`:

```csharp
namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// A serialisable name/value pair representing a single claim captured at grant time.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="System.Security.Claims.Claim"/> is intentionally not used here.
/// <c>Claim</c> is not serialisable without custom converters, carries a back-reference
/// to <c>ClaimsIdentity</c>, has mutable properties, and depends on
/// <c>System.Security.Claims</c> semantics (issuer, original issuer, value type) that
/// have no meaning in the store serialisation context. <c>ClaimRecord</c> is the
/// serialisation-stable projection.
/// </para>
/// <para>
/// Store implementors that need to round-trip <c>Claim</c> objects (e.g. when constructing
/// a <c>ClaimsPrincipal</c> for access token issuance) convert between <c>ClaimRecord</c>
/// and <c>Claim</c> at the boundary; the store itself never sees <c>Claim</c>.
/// </para>
/// </remarks>
public readonly record struct ClaimRecord(string Type, string Value);
```

The rationale for this type over the alternatives:

**Why not `System.Security.Claims.Claim`?**

`Claim` is a live object with a back-reference to its parent `ClaimsIdentity`, mutable
properties (`Properties`, `Subject`), and BCL semantics around `Issuer` and `OriginalIssuer`
that have no meaning in a store serialisation context. It is not serialisable to JSON without
a custom converter; the default `System.Text.Json` serialiser will either fail or drop
properties silently. Carrying `Claim` on a store entry record would force every store
implementor to write and maintain a custom JSON converter, adding friction and a common source
of serialisation bugs. The project's principle of minimal friction for store implementors
rules it out.

**Why not `IReadOnlyDictionary<string, string>`?**

A dictionary representation collapses multiple claims with the same type (e.g. multiple
`"role"` values, multiple `"group"` values) into a single entry or requires a
`IReadOnlyDictionary<string, IReadOnlyList<string>>` shape. Multi-valued claims are
common in real applications. A flat dictionary cannot represent them correctly. The
more-correct dictionary shape is more complex and still requires explanation and
type-converter effort from store implementors. The list-of-pairs representation is
simpler, round-trips cleanly, and represents multi-valued claims naturally.

**Why not `IReadOnlyList<(string Type, string Value)>`?**

A plain value tuple serialises poorly: `System.Text.Json` emits `{"Item1": ..., "Item2": ...}`
for unnamed tuples, and named tuples (`(string Type, string Value)`) are only named at the
call site — the names are erased at runtime and the serialiser sees unnamed `Item1`/`Item2`.
A named record struct with explicit `Type` and `Value` properties serialises correctly out of
the box, is readable in JSON output, and is unambiguous in XML doc and error messages.

**Why `readonly record struct` rather than `record class`?**

A value type avoids a heap allocation per claim. Claims lists are read-only in the store
context and are created once at grant time. A `record struct` with only two `string` fields
has no boxing cost when used in `IReadOnlyList<ClaimRecord>` (the list implementation
boxes, but the struct fields themselves do not). The `readonly` modifier prevents mutation
after creation. The `record` modifier provides value equality and a `ToString()` suitable
for diagnostics without hand-writing `Equals`/`GetHashCode`.

**Nullable annotation.** The `Claims` property is **not** declared `required` on either entry
record — it is `IReadOnlyList<ClaimRecord>?` (nullable, defaults to `null`). The rationale:

- For pure OAuth 2.0 grants (no OIDC, no custom claims), an empty or null claims list is a
  valid and common case. Making it `required` would force callers to pass `[]` or
  `Array.Empty<ClaimRecord>()` even when no claims are expected, adding noise with no safety
  benefit.
- Null is semantically distinct from empty: null means "no claims were captured at grant
  time" (e.g. the host application did not populate them), while an empty list means "claims
  were explicitly evaluated and none were present". The token issuance pipeline can distinguish
  these cases if needed.
- Store implementors must persist and replay the value faithfully including the null/empty
  distinction; this is documented in the XML doc on each property (see §4).

### 4. Entry record amendments

This ADR amends ADR 0008 §2 (`AuthorizationCodeEntry`) and §3 (`RefreshTokenEntry`) by adding
the following property to each record's property table:

| Property | Req | Type | Notes |
|---|---|---|---|
| `Claims` | | `IReadOnlyList<ClaimRecord>?` | Snapshot of the user claims captured at authorisation time. `null` for pure OAuth 2.0 flows where no custom claims are carried. Store implementors MUST persist and replay this value faithfully, including the null/empty distinction. The token endpoint reads this value to populate access token claims; it MUST NOT re-read the identity store at rotation time. |

**`AuthorizationCodeEntry`**: The `Claims` snapshot is populated by the authorization endpoint
at code issuance time, immediately after the host application's interaction layer completes
authentication and consent. The host application is responsible for collecting the claims it
wants carried in access tokens and providing them to the authorization endpoint through the
interaction context or an equivalent seam (TBD in the interaction ADR). The framework stores
them verbatim.

**`RefreshTokenEntry`**: At auth code exchange (`TryRedeemAsync` returns `Redeemed`), the token
endpoint copies `AuthorizationCodeEntry.Claims` verbatim to `RefreshTokenEntry.Claims`. All
subsequent rotations carry the same list. The token endpoint MUST NOT modify the list
between rotations.

### 5. No claim transformation pipeline in this ADR

A claim transformation pipeline (`IClaimsTransformer` or equivalent) is **not** a blocker
for this decision and is explicitly deferred. The rationale:

The snapshot model is self-consistent without a transformer: claims are set once at grant time
and replayed faithfully. A transformer is needed if operators want to override the snapshot —
for example, to re-fetch claims from the identity store on every issuance (achieving Option A
semantics as an opt-in), or to enrich claims at issuance time without changing the stored
snapshot. Both use cases are legitimate. Neither is blocked by the current decision; they add
functionality rather than correcting a defect.

Adding a transformer now, before the access token and ID token issuance pipelines exist (those
are open ADR questions — see issues #205 and #206), would design a hook whose contract
depends on systems that have not been designed yet. The shape of `IClaimsTransformer` is
tightly coupled to how access tokens are assembled (claims mapping, audience, etc.); those
decisions must come first.

The transformer is tracked as a future addition in §6 below. Its absence does not leave the
framework in an incomplete state: the snapshot model is fully functional without one.

### 6. Forward-compatibility path for claim transformation

When access token generation is designed (issue #205) and ID token generation is designed
(issue #206), a separate ADR will design the claim transformation pipeline. That ADR will
specify:

- The interface (`IClaimsTransformer` or equivalent) and its method signature
- What the transformer receives (the `ClaimRecord` snapshot, the `ClaimsPrincipal`, the
  request context, the scopes)
- When the transformer is invoked (at access token mint, at ID token mint, or both)
- How operators who want re-fetch semantics implement it (by ignoring the snapshot and
  loading from the identity store inside the transformer)
- How the default implementation (identity transformer — return the snapshot unchanged) is
  registered

The `ClaimRecord` type introduced in this ADR is the transfer object between the store and the
transformer pipeline. Its design (flat `Type`/`Value` pairs, no `Claim` object) is forward
compatible with that pipeline.

---

## Rejected Alternatives

### Option A — Re-fetch claims on every issuance

**Rejected.** Without a claim transformation hook, re-fetch adds a hidden I/O dependency on
every token issuance (including rotation) with no extension point for operators. The token
endpoint would silently read the identity store on the hot path, making it non-deterministic
and impossible to test without a live identity store. There is no protocol requirement for
re-fetch; the consistency requirement in the spec (RFC 6749 §6) applies to scope, not to
arbitrary claim content.

Re-fetch *with* a hook (as Duende IdentityServer's `IProfileService` provides) is a defensible
design. The difference from snapshotting is that it makes the live-read the default and requires
an opt-out for consistency, rather than making consistency the default and requiring an opt-in
for live-read. Given that ZeeKayDa.Auth's design principles favour explicit over implicit and
testability over convenience, snapshotting is the more principled default.

Re-fetch can always be achieved by an operator who registers a claim transformer that ignores
the snapshot (see §6). The reverse — achieving snapshot consistency without a framework hook
when re-fetch is the default — requires replacing the store or the token endpoint, which is
far more invasive. Choosing snapshot as the default preserves the easier migration path.

### `IReadOnlyDictionary<string, string>` (flat dictionary)

**Rejected.** Cannot represent multi-valued claims (multiple `"role"` values, multiple
`"group"` values) without a schema change. Multi-valued claims are common in real applications.
A flat dictionary would silently drop all but the last value for any repeated claim type, or
require a more complex `IReadOnlyDictionary<string, IReadOnlyList<string>>` shape. The
list-of-pairs representation is simpler and handles multi-valued claims naturally.

### `System.Security.Claims.Claim`

**Rejected.** Not serialisable without a custom `System.Text.Json` converter.
Carries `ClaimsIdentity` back-reference and mutable properties. Adding a custom converter
requirement to the store contract would block store implementors using AOT-compiled JSON
contexts (which this project already uses — `ZeeKayDaJsonSerializerContext` exists in the
codebase). A custom converter cannot be added to an AOT context without code-generating it.

### `IReadOnlyList<(string Type, string Value)>` (value tuple)

**Rejected.** Value tuples serialise as `Item1`/`Item2` under `System.Text.Json`, not as
`Type`/`Value`. Named tuple names are compile-time only — they do not survive the type
system. A named record struct is the correct idiom for a named, serialisable value pair.

### Divergent strategy (snapshot on auth code, re-fetch on rotation)

**Rejected.** Produces access tokens whose contents change across the grant lifetime without
any user interaction. The first access token (from code exchange) would contain snapshot claims;
subsequent tokens (from rotation) would contain re-fetched claims. This inconsistency is
observable to clients and is not a meaningful security improvement over pure snapshotting.
The stale-claims concern that motivates re-fetch-on-rotation is better addressed by
shortening access token lifetimes than by silently changing token contents mid-session.

---

## Consequences

### Positive

- **Token issuance pipeline is deterministic and independently testable.** The token endpoint
  does not read the identity store at rotation time. Claims in any access token are exactly
  the `Claims` on the consumed `RefreshTokenEntry`. Tests for the token endpoint do not
  require a live identity store.
- **Consistent access token contents across a grant lifetime.** Clients that cache claim
  decisions (e.g. a resource server that caches role memberships from a JWT for the lifetime
  of the token) see stable contents across all access tokens minted from the same grant.
- **No hidden hot-path I/O.** The identity store is read exactly once per interactive
  authentication, not on every token issuance. The performance characteristics of the token
  endpoint are bounded by store lookups, not by arbitrary identity store latency.
- **Forward compatible with a claim transformation pipeline.** The `ClaimRecord` type is
  designed as the transfer object between the store and the (future) transformer pipeline. No
  breaking change to the entry records is needed when the transformer is added.
- **Store implementors can serialise `ClaimRecord` out of the box.** `System.Text.Json`
  serialises `readonly record struct` types with named properties correctly without a custom
  converter, including in AOT contexts.

### Negative / Trade-offs

- **Claims go stale within a grant lifetime.** A role change, account suspension, or group
  membership update is not visible in access tokens until the user re-authenticates. This is
  the correct trade-off when access token lifetimes are short (the recommended mitigating
  control), but operators who choose long access token lifetimes must understand the
  implication.

  *Mitigation*: the framework XML doc on `Claims` on both entry records MUST state the staleness
  behaviour and the recommended access-token lifetime guidance. When the transformer pipeline
  is added (§6), operators who require fresh claims on every issuance can implement an
  `IClaimsTransformer` that loads from the identity store.

- **Store implementors must persist the claims list faithfully.** A store that silently drops
  or truncates `Claims` would cause the token endpoint to issue access tokens with incomplete
  claims. The XML doc and the deployment guidance in ADR 0008 §8 must call this out explicitly.
  The null/empty distinction must also be preserved.

- **`ClaimRecord` is a new public type in the store contract.** Adding it now, before any
  implementation exists, is the right time — but it adds one more type that custom store
  implementors must understand. The type is minimal (two string properties) and the XML doc
  explains why `Claim` was not used.

- **No claim transformation pipeline today.** Operators who need re-fetch semantics must wait
  for the transformer pipeline (§6). This is an acceptable gap: the snapshot model is fully
  functional and consistent; re-fetch is an enrichment, not a baseline requirement.

---

## Security Considerations

### Stale claims and authorisation decisions

The most security-sensitive stale-claims scenario is a claim that grants elevated access —
a role, group, or entitlement — that is revoked after a grant is established. Under the
snapshot model, the revoked claim remains in the access token until the grant expires or the
user re-authenticates.

The correct mitigation is access token lifetime, not claims freshness. An access token with
a 15-minute lifetime limits the blast radius of a stale revoked-role claim to 15 minutes.
RFC 9700 §4.2.2 recommends short-lived access tokens for exactly this reason. A snapshotting
model with 15-minute access tokens and 14-day refresh tokens means a role revocation takes
effect at most 15 minutes after the next rotation (or immediately on next rotation if the
transformer re-fetches — but that is the transformer's responsibility, not the snapshot
model's).

Operators who require immediate revocation (e.g. for high-privilege accounts) MUST use
token introspection (RFC 7662) or short-lived reference tokens backed by a real-time
lookup, not rely on claim freshness in JWT access tokens. This guidance must appear
in the framework deployment documentation.

### Claims as bearer data

The `Claims` snapshot on `RefreshTokenEntry` persists across the lifetime of the grant
(up to `RefreshTokenLifetime`, default 14 days). The entry is encrypted at rest by
`IDataProtectionProvider` per ADR 0008 §4b. Any claim that constitutes personal data
(name, email, phone number, etc.) is subject to the same data-at-rest protection
requirements that apply to `Sub` and `Scope` on the entry. Store implementors using a
custom backend MUST apply equivalent protection.

The `AuthorizationCodeEntry.Claims` snapshot has a much narrower window (60-second code
lifetime) but is subject to the same rule for completeness.

### Claims injection via the snapshot

The snapshot is written at authorisation time by the framework, using claims provided by
the host application's interaction layer. The framework does not validate or sanitise
claim values. A host application that includes attacker-controlled strings in claims
(e.g. by reflecting untrusted input directly into a `"name"` claim) is responsible for
that content. The framework's responsibility is accurate round-trip — what is stored is
what is issued.

### Volume and storage cost

`Claims` adds to the per-entry payload. A typical OIDC token set may include 5–20 claims
(sub, name, email, roles × N, groups × M). At 100 bytes per claim on average, 20 claims
add ≈ 2 KB per entry. For `RefreshTokenEntry` this is persisted for up to 14 days. The
capacity planning numbers in ADR 0008 §8 should be revisited by operators with large
claim sets; the base estimate (a few hundred bytes per entry) no longer applies when
`Claims` is populated.
