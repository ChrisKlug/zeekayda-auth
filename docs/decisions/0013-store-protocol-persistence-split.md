# ADR 0013 — Authorization-Code Store: Protocol / Persistence Split

Status: Accepted   ·   Date: 2026-07-15   ·   Issue: #375

> **Scope: authorization-code store only.** The refresh-token store's equivalent reshape (family
> metadata, whole-family revocation, absolute-lifetime caps) is a separate, later design — see
> [ADR 0014](./0014-refresh-token-grant-store.md), which reuses the `StoreKey` type this ADR
> introduces but diverges from its opaque key-value shape.
>
> **Relationship to ADR 0008.** This ADR does not restate the redemption protocol ADR 0008 already
> settles (single-use enforcement, replay/reuse detection, handle hashing, at-rest encryption,
> fail-closed I/O, clock-skew-tolerant logical expiry, the four-case redemption outcome). It
> re-homes *where that protocol lives* — into framework-owned code — and reshapes *what a third
> party implements* down to a dumb key-value primitive.
>
> **Security sign-off (2026-07-15): ✅ granted, for the authorization-code store only.** This ADR
> changes one ADR 0008 behaviour: the redemption tombstone becomes a small envelope with a
> plaintext `FamilyId` (see Decision), replacing the all-ciphertext tombstone, so that
> `AlreadyRedeemed{FamilyId}` (RFC 9700 §2.1.1 replay handling) survives a Data-Protection key
> rotation. Security reviewed and approved the plaintext `FamilyId` on its own merits: `FamilyId`
> is a random GUID used only as a non-secret correlation/revocation-lookup identifier — revocation
> is driven only by the plaintext `FamilyId` value itself, never by the raw code handle, and
> `RevokeFamilyAsync` is framework-internal, unreachable by a read-only store observer — a leaked
> `FamilyId` grants no capability, forges no token, enables no redemption — so this discloses
> correlation, not a bearer credential. Two facts specific to the
> *code* store make the trade clearly correct: the tombstone's backend TTL is the code's own
> seconds-to-minutes lifetime, so the cleartext exists only briefly; and each authorization code
> maps to a distinct, freshly-minted family, so a `FamilyId` appears in at most one code tombstone
> — there is no rotation chain to correlate (chains exist only in the refresh-token store, which
> requires its own, separate sign-off — see ADR 0014). The rotation-survival benefit is a strict
> security improvement and outweighs this narrow, short-lived correlation surface.

## Decision

`IAuthorizationCodeStore` stops being a third-party extension point and becomes
**framework-sealed**: it stays `public` (so `ZeeKayDa.Auth.AspNetCore` can inject it
cross-assembly) but gains an `internal` interface member that only `[InternalsVisibleTo]`
assemblies can satisfy, so a third party attempting to implement it gets a compile error. The
framework ships one sealed coordinator, `AuthorizationCodeStore`, that owns everything
protocol-critical listed above.

The one thing a third party still implements is `IAuthorizationCodeBackingStore` — a narrow,
"dumb" key-value primitive with three methods (`TryInsertAsync`, `GetAsync`, `RemoveAsync`) that
stores opaque, already-encrypted bytes under already-hashed keys (`StoreKey`, a struct whose
constructor is framework-internal, so a backing store can never fabricate a key from a raw
handle). The one hard invariant is that `TryInsertAsync`'s insert-if-absent test and write MUST be
a single atomic operation (Redis `SET NX`, a unique-constraint `INSERT`, a conditional Cosmos
create) — single-use enforcement rides entirely on it. `GetAsync` MUST NOT catch a transport fault
and return `null`; only a confirmed-absent key returns `null` (a swallowed fault read as "no
tombstone" would silently reopen a replay window). The framework wraps every thrown exception as
`ZeeKayDaStoreException` (ADR 0006) and rethrows `OperationCanceledException` unwrapped.

The redemption tombstone becomes an envelope — `{ FamilyId: plaintext string, ProtectedSecret:
DP-ciphertext }` — instead of a single opaque blob (see security sign-off above). The coordinator
catches `Unprotect` failures at two sites with opposite outcomes: an undecryptable *entry* is
unusable, so it returns `NotFound`; an undecryptable tombstone's `ProtectedSecret` still yields the
cleartext `FamilyId`, so it returns `AlreadyRedeemed{FamilyId}` — replay detection and family
revocation survive even when the DP key has rotated.

`AddAuthorizationCodeStore<T>()` and the two first-party registration methods keep their names but
now require `T : IAuthorizationCodeBackingStore` and wire the sealed coordinator over it. The
public outcome type is renamed `AuthorizationCodeRedemptionOutcome` →
`AuthorizationCodeRedemptionResult` for consistency with `ClientAuthenticationResult` /
`SigningResult` (pre-1.0 rename, no compatibility impact). The conformance kit for the one residual
invariant (`TryInsertAsync` atomicity, `GetAsync` fail-closed) ships in a separate package,
`ZeeKayDa.Auth.TestKit`, so a third party can derive and run it without needing
`[InternalsVisibleTo]` access to `ZeeKayDa.Auth` itself.

## Why

The epic #352 extension-API review ran the "hand `IAuthorizationCodeStore` to a competent .NET dev
who has never seen this codebase and say *implement a new one*" test, and it failed: an
implementer had to independently get right several correctness-bearing MUST/MUST-NOT clauses
carried only in prose doc-comments, at least three of them directly security-critical (hash the
handle before keying on it; encrypt the entry at rest; perform check-and-consume atomically). Per
Design Principle 6 ("docs are not a mitigation"), that many naive-implementation-violates-while-
compiling invariants on one extension point is an API-design problem. The only thing a third party
legitimately wants to vary is *where the bytes live* — everything else is fixed protocol.

- **Keep the open interface plus a whole-store conformance kit (rejected).** A kit still requires
  the implementer to know it exists and run it, and does nothing for invariants the CLR can't
  express as a test (e.g. "encrypt entries"). The reshape makes those invariants structurally
  unrepresentable instead, shrinking the residual test target to one primitive's atomicity plus its
  fail-closed contract.
- **Make `IAuthorizationCodeStore` `internal` to seal it (rejected).** `ZeeKayDa.Auth.AspNetCore` is
  a separate assembly that must consume (inject) the interface; an `internal` interface would break
  that. The internal-member seal blocks implementation by non-friend assemblies while leaving
  consumption open — the asymmetry actually needed.
- **A single shared backing interface for both the code and refresh-token stores (rejected).** The
  two stores diverge on lifetime (seconds vs. months) and durability pressure (a lost code just
  fails one authorization; lost refresh tokens force mass re-authentication). Forcing one
  registration would push consumers to over- or under-provision; the two stores are free to
  diverge on backing shape independently.
- **Encrypt `FamilyId` too and add an `AlreadyRedeemed.FamilyUnrecoverable` case (rejected).**
  `FamilyId` is a non-secret random GUID, so encrypting it buys nothing; leaving it cleartext lets
  replay detection and family revocation both survive a DP key rotation, strictly better, with no
  churn to the public outcome union.
- Naming the backing-store interface went through several rejected candidates —
  `IExpiringKeyValueStore` (too generic, invites one shared instance across incompatible stores),
  `IAuthorizationCodeRepository` (implies DDD/EF-Core query/unit-of-work machinery this type doesn't
  have), `*Persister`/`*Persistence` (non-idiomatic, foregrounds the act over the thing, reads as
  write-only). `BackingStore` is the established .NET term for "where the bytes live behind a
  richer abstraction," which is exactly this type's role.

## Consequences

Pre-publication blast radius (acceptable — nothing is published, see `CONTRIBUTING.md`'s Pre-1.0
Stability Policy): introduces `StoreKey` and `IAuthorizationCodeBackingStore`; makes
`IAuthorizationCodeStore` framework-sealed; renames the outcome type; rewrites the first-party
`InMemory*`/`DistributedCache*` stores as thin backing adapters; changes the tombstone shape.
Endpoint callers are unaffected.

The CLR cannot prove a given `TryInsertAsync` implementation is actually atomic — that ceiling is
irreducible and is mitigated only by mapping guidance (Redis `SET NX`, SQL unique-constraint
`INSERT`, Cosmos conditional create, etc.) and the `ZeeKayDa.Auth.TestKit` conformance case, not
eliminated.

A read-only store observer can now correlate a redeemed code's tombstone to its refresh-token
family via the cleartext `FamilyId` — accepted per the security sign-off above (non-bearer GUID,
short-lived, one family per code).
