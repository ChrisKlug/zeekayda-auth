# Token stores

Rules shared by the authorization-code store and the refresh-token store, plus the code store's own
redemption protocol. The refresh-token grant model is `refresh-token-grants.md`.

## Decisions in force

**The framework owns the protocol; a third party owns only where the bytes live.**
`IAuthorizationCodeStore` and `IRefreshTokenStore` are coordinators, not extension points: single-use
enforcement, replay and reuse detection, handle hashing, at-rest encryption and clock-skew-tolerant
expiry are all framework code. Each stays `public` so `ZeeKayDa.Auth.AspNetCore` can inject it
cross-assembly, and each carries an `internal` member only friend assemblies can satisfy — publicly
consumable, not third-party implementable, which is the asymmetry actually needed. Handing the old
open interface to a competent .NET developer failed the "implement a new one" test: it carried at
least three security-critical MUST clauses in prose doc comments alone.

**Two backing contracts, deliberately not unified.** `IAuthorizationCodeBackingStore` is an opaque
key-value primitive; `IRefreshTokenGrantStore` is a queryable row store. The two diverge on lifetime
(seconds versus months), on durability pressure (a lost code fails one authorization; lost refresh
tokens force mass re-authentication) and on addressability, so a single shared registration would
push consumers to over- or under-provision one of them. They are registered and replaced separately.

**A backing store can never see or fabricate a raw handle.** Keys arrive as `StoreKey`, whose
constructor is framework-internal; the framework hashes the handle before keying anything on it,
because the handle is itself a bearer credential and store read access — ops tooling, backups, log
sidecars — must not expose it (RFC 6819 §5.1.4.1.3). "Hash before you key" is therefore
unrepresentable in third-party code rather than documented. The key-space layout (hash algorithm,
encoding, namespacing) is an implementation detail of each first-party store, differs between the
two, and nothing downstream may depend on it.

**Fail-closed I/O, with no discretion left to the implementer.** The framework wraps every native
fault as `ZeeKayDaStoreException` and rethrows `OperationCanceledException` unwrapped. A read MUST
NOT catch a transport fault and report absence: `null` means confirmed-absent and nothing else,
because a fault masked as absence reads as "not redeemed" or "no such token" and silently reopens a
replay window. Any I/O failure during issuance aborts the response — nothing is handed to a client
whose credential the framework failed to persist.

**Single use is a record of redemption, not a deletion.** Redemption writes a tombstone through the
same atomic insert-if-absent that decides the race, then removes the entry. Deleting instead of
tombstoning would make a replay indistinguishable from `NotFound` and defeat family revocation
entirely.

**`TryRedeemAsync` is single-phase: the caller mints `familyId` before the call.** The tombstone is
written with that id inside the one atomic insert, so every future `AlreadyRedeemed` is guaranteed to
carry a non-null, revocable `FamilyId`.

**The tombstone is an envelope with a cleartext `FamilyId`, not one opaque blob.** The two decryption
failures have deliberately opposite outcomes: an undecryptable *entry* is unusable and resolves
`NotFound`, while an undecryptable tombstone still yields the cleartext id and resolves
`AlreadyRedeemed{FamilyId}` — so replay detection and family revocation survive a Data Protection key
rotation. Security signed off on the cleartext id: it is an unguessable random value used only for
correlation and revocation lookup, it grants no capability if leaked, and it lives only as long as
the code's own tombstone.

**Tombstone retention is the code's own lifetime — `ExpiresAt + ClockSkewTolerance`, never the
refresh-token lifetime.** Accepted residual: a code replayed after its tombstone has expired resolves
`NotFound`, so no family revocation fires. The code is unredeemable by then, so the missed revocation
costs an attacker nothing it could have used.

**Client binding is checked without consuming.** A mismatch between the presented `client_id` and the
stored one returns `ClientMismatch` and leaves the record intact. Consuming on mismatch would let an
attacker who captured a credential but not the legitimate `client_id` burn it as a denial of service
— and, on the refresh-token store, trigger a family revocation the legitimate client never asked for.

**One code, one freshly minted family, and `familyId` comes from a CSPRNG.** Nothing in the store
enforces this — `TryRedeemAsync` accepts whatever string it is handed — so the token-issuing endpoint
MUST mint a fresh, never-reused value of at least 128 bits from a cryptographic RNG; `Guid.NewGuid()`
is not one. The cleartext-`FamilyId` sign-off is predicated on one code mapping to one family, so
reusing an id across codes extends a per-code correlation surface into a chain nobody assessed.

**No store is auto-registered, and absence fails startup.** A startup validator fails the host when
either coordinator interface is unregistered, and every registration method throws
`InvalidOperationException` on a second registration for the same interface rather than letting an
earlier call silently win. In-memory registrations warn in `Development`; outside it they fail
startup unless the call passed `allowOutsideDevelopment: true`, which downgrades the failure to a
`Critical` warning on every startup. That flag is a parameter on the one registration method that
needs it, never a bindable option — it is meaningless without the call it qualifies.

**Options placement.** `AuthorizationCodeLifetime` (60s) on `AuthorizationEndpoint`;
`RefreshTokenLifetime` (14 days, no enforced upper bound — operators own that trade-off) on
`TokenEndpoint`; `ClockSkewTolerance` (5s) on the shared root, applied as accept-grace on every
liveness check (`now >= ExpiresAt + ClockSkewTolerance`).

**Retaining Data Protection keys is an operator obligation, and its failure mode is silent.** A key
removed from the ring before every token it protected has expired makes those tokens permanently
undecryptable; because a failed decrypt is fail-closed to `NotFound`, the visible symptom is users
being logged out with no error at all.

**Nothing that ships today is a production store.** The in-memory and `IDistributedCache`-backed
stores are development and test only. `IDistributedCache` has no atomic check-and-set, so
insert-if-absent and the grant-store compare-and-set are both read-then-write with a real TOCTOU
window, and an evicting cache can drop a tombstone before its TTL. Production means a backend with a
native atomic primitive, registered through the typed path.

**The conformance kit is the last resort, not the sanctioned path.** `ZeeKayDa.Auth.TestKit` ships
derive-and-run fixtures for both backing contracts, in its own package so a third party needs no
`InternalsVisibleTo` grant. It covers only what the CLR cannot make structurally true — an
operation's atomicity, fail-closed faulting, revocation completeness. Anywhere the wrong thing can be
made unrepresentable instead, it is, and the kit is not offered as an alternative to that.

## Tried, didn't work

- **A third-party-implementable protocol store.** The original shipped contract for both stores let a
  consumer implement the whole redemption protocol. Reversed: the correctness-bearing invariants a
  naive implementation violated while compiling outnumbered the one thing a third party actually
  wants to vary. The coordinator plus a narrow backing primitive is the fix; making the coordinator
  interface `internal` is not, because the ASP.NET Core adapter must still consume it.
- **Two-phase redemption — `TryRedeemAsync` followed by `CompleteRedemptionAsync(token, familyId)`.**
  A crash or dropped connection between the two calls leaves a tombstone with a null `FamilyId`, so a
  later replay resolves `AlreadyRedeemed(null)`: nothing to revoke, RFC 9700 §2.1.1 violated. The
  durability gap was in the interface shape, so no backend could have fixed it — only deleting the
  second phase did.
- **An operator-configurable tombstone TTL.** Shipped, then removed. Every off-default value is
  either harmful (shorter than the code's own lifetime, silently defeating replay detection with no
  startup error) or useless (longer, holding space for a code that can no longer be redeemed).
