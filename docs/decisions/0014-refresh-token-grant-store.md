# ADR 0014 — Refresh-Token Grant Store: Queryable Persisted-Grant Model

**Status:** Accepted (security review complete — all three items signed off, see banner)
**Date:** 2026-07-15 (issue #376, from the epic #352 extension-API review)

> **Relationship to ADR 0013.** This ADR is the refresh-token counterpart to
> [ADR 0013](./0013-store-protocol-persistence-split.md), which reshaped the *authorization-code*
> store. It does **not** restate the concepts the two stores share — read ADR 0013 for all of the
> following, which apply here **unchanged**: the `StoreKey` opaque-hashed-key type and its
> framework-only constructor (0013 §2); the internal-member **sealing mechanism** that keeps a
> coordinator interface publicly *consumable* but not third-party *implementable* (0013 §1); the
> fail-closed **`Guarded(...)`** wrapper that maps native store faults to `ZeeKayDaStoreException`
> and rethrows `OperationCanceledException` unwrapped (0013 §8); the **accept-grace logical-expiry**
> rule `now >= ExpiresAt + ClockSkewTolerance` (0013 §6); and the general "coordinator owns the
> protocol, the extension point owns only where the bytes live" split. This ADR describes only what
> is *genuinely different* for refresh tokens and points back to ADR 0013 for what is identical.
>
> **Scope: refresh-token store only.** The authorization-code store stays exactly as ADR 0013
> defines it and is not touched here. ADR 0013's forward pointer to "a later refresh-token reshape
> (family metadata, whole-family revocation, absolute-lifetime caps)" is *this* ADR — but the shape
> it lands on diverges from the `StoreKey` + backing-KV model 0013 anticipated (see Context and the
> "single shared backing interface" rejected alternative).
>
> **Ordering dependency.** ADR 0013 merges via issue #375; this ADR (issue #376) is authored on a
> separate branch off `main`. The cross-references above resolve once #375 lands. #376's
> *implementation* must not start before both this ADR's security sign-off (below) and ADR 0013 are
> merged.

> **⚠️ Security sign-off: REQUIRED, NOT YET GRANTED (as of 2026-07-15).** This ADR must be reviewed
> before #376's implementation starts. Sign-off is scoped to the **refresh-token store
> specifically** and is **not** inherited from ADR 0013's authorization-code sign-off — the
> refresh-token store has a materially larger cleartext surface and longer-lived records, so it
> needs its own assessment. The three items requiring explicit sign-off:
>
> 1. **Cleartext queryable columns replacing an all-encrypted-blob model.** `FamilyId`,
>    `Subject`, `ClientId`, `FamilyAbsoluteExpiry`, `ExpiresAt`, and `Status` are stored as
>    non-secret cleartext columns so reuse/revoke/mismatch/expiry are decidable as SQL predicates
>    over live rows (§2, §3). This is a bigger cleartext surface than ADR 0013's single plaintext
>    `FamilyId`. Needs assessment of: what a read-only store observer learns; how the subject column
>    should be protected given the subject is PII; and whether the subject column's **correlation**
>    risk differs from `FamilyId` correlation risk given subjects are long-lived, stable identifiers
>    that recur across many families and over months, unlike a per-family random GUID
>    (§ "Security Considerations", item 1).
> 2. **Mark-don't-delete + absolute-family-lifetime cap vs. the accept-grace clock-skew rule.**
>    Consumed/revoked rows are retained as tombstones, not deleted, until self-cleaned past
>    `FamilyAbsoluteExpiry` (§5, §6). Needs confirmation that the interaction of the retained
>    tombstone, the `min(now + RefreshTokenLifetime, FamilyAbsoluteExpiry)` clamp, and the
>    accept-grace expiry window (§6) does not open a window where a token is treated as live past
>    the family's absolute cap, or where a tombstone is swept while still needed for reuse
>    detection.
> 3. **The single `Unprotect` catch-site simplification.** Unlike ADR 0013 §7's deliberate
>    two-catch-site asymmetry, this store decrypts only on the `Consumed` happy path (§4, §7).
>    Needs confirmation that collapsing to one catch site does **not** reintroduce a fail-open path
>    that 0013's two-site design was protecting against — specifically that reuse and revocation
>    detection never depend on a successful decrypt.
>
> **Security review outcome (2026-07-15):**
>
> - **Item 1 — cleartext columns / `Subject`: ✅ SIGN-OFF (supersedes the 2026-07-15 BLOCK; see
>   Changelog).** `ClientId`, `FamilyAbsoluteExpiry`, `ExpiresAt`, `Status`, and the random-GUID
>   `FamilyId` clear: none is a bearer credential, they disclose only operational/correlation
>   metadata already implied by a grant's existence, and `FamilyId`'s reasoning transfers directly
>   from ADR 0013's granted sign-off (random 128-bit, unguessable, no capability if leaked).
>   `HandleHash` is a bare SHA-256 but its preimage is a 256-bit random handle, so it resists
>   reversal. **The subject column also clears — as an honestly-named cleartext `Subject` string, not
>   a hash.** The original design stored it as `StoreKey(H(entry.Sub))`, a bare unkeyed SHA-256, and
>   the first review BLOCKED that: over a guessable, low-entropy, enumerable preimage (sequential
>   ids, emails) a read-only store observer reverses the hash by rainbow table trivially, so
>   "hashed" bought no confidentiality against the very attacker in scope — it only created false
>   confidence that a control existed. The maintainer's revision draws the honest conclusion. The
>   HMAC-with-pepper fix the first review proposed was reconsidered and **rejected** for a correct
>   operational reason: `RevokeBySubjectAsync` is a security control that must *never* fail to match,
>   which is fundamentally incompatible with a keyed secret that gets rotated — rotating the pepper
>   silently breaks subject-level revocation for every pre-rotation row, and a two-pepper scheme only
>   defers the same failure at real complexity cost. The two reference implementations this ADR is
>   modelled on confirm the honest posture: **neither Duende IdentityServer (`PersistedGrant.SubjectId`)
>   nor OpenIddict (`OpenIddictToken.Subject`) hashes the subject at all** — both store it as a plain
>   PII/foreign-key column and hash only the token *handle* (this ADR's `HandleHash`). The subject is
>   therefore protected the same way they protect it and the same way this ADR already accepts
>   cleartext `FamilyId`: it is **not a bearer credential**, and its confidentiality rests on
>   **database-level access control (least-privilege roles), encryption at rest (disk/backend-level),
>   and standard PII-handling policy over the whole grant table** — infrastructure-layer controls,
>   not an illusory application-level hash. **Threat-model note on cleartext vs. the blocked hash:**
>   for the read-only-DB-access attacker in scope, cleartext is *not* materially worse than the
>   blocked SHA-256 — that hash was reversible for exactly this (guessable) input class, so both
>   expose the raw subject; cleartext simply removes a reversal step that was already cheap and stops
>   overstating the protection. The residual, *inherent* correlation risk is unchanged from what the
>   hashed design already carried: because the column is deterministic and queryable, an observer with
>   DB read can see that N families share one subject and correlate a user's grants across families
>   over months — stronger than `FamilyId`'s per-chain scope. That is intrinsic to *having a queryable
>   subject column at all* (the price of `RevokeBySubjectAsync`), it was never closed by the hash, and
>   it is accepted here and called out in Security Considerations. **Note on ADR 0008:** this does
>   move the subject from ADR 0008's encrypted-payload-only treatment to an additional cleartext
>   queryable column (the encrypted copy still lives inside `ProtectedPayload`); that at-rest exposure
>   is the deliberate, necessary cost of making by-subject revocation a SQL predicate, and matches the
>   reference implementations.
> - **Item 2 — mark-don't-delete vs. absolute cap vs. accept-grace: ✅ SIGN-OFF.** The arithmetic
>   composes safely. A grant is honoured only while `Status == Active` and
>   `now < ExpiresAt + ClockSkewTolerance`; the clamp guarantees `ExpiresAt <= FamilyAbsoluteExpiry`,
>   so the latest honour instant is `FamilyAbsoluteExpiry + skew` — the accept-grace band applied
>   consistently, not an over-run of policy. The sweep predicate
>   `family_absolute_expiry < now - skew` deletes a row only *after* `now > FamilyAbsoluteExpiry +
>   skew`, i.e. strictly after every token in that family has passed its own accept-grace window, so
>   a tombstone is never physically removed while still needed for reuse detection. `FamilyAbsoluteExpiry`
>   is shared verbatim across the whole family, so the family is swept atomically — no split-sweep
>   leaves a live sibling without its family's tombstones. Status-before-expiry ordering in
>   `TryConsumeAsync` means the reuse/revoked signal is only ever lost to `NotFound` after the token
>   is independently expired and unredeemable anyway. The `DateTimeOffset.MaxValue` sentinel disables
>   cap + sweep (unbounded row growth), which is a resource concern, not a fail-open one, and is a
>   warned, explicit opt-in. **Non-blocking implementation note:** guard `now + RefreshTokenLifetime`
>   and `ExpiresAt + ClockSkewTolerance` against `DateTimeOffset` overflow near the sentinel.
> - **Item 3 — single `Unprotect` catch site: ✅ SIGN-OFF.** Verified against the §4 flow: `NotFound`
>   (null), `Revoked`, `AlreadyConsumed` (reuse), accept-grace expiry, and `ClientMismatch` are all
>   decided from cleartext columns *before* the CAS and *before* any `Unprotect`; the CAS pivots on
>   the `Status` column; the lost-race re-read branch also reads cleartext only. The sole `Unprotect`
>   runs *after* the CAS has already marked the row `Consumed`, on the happy path, and its failure
>   degrades to `NotFound` — fail-**closed** (the token is already dead, no successor issued, no reuse
>   enabled). No security decision anywhere in the coordinator rides on a successful decrypt, so
>   collapsing to one catch site reintroduces no fail-open path. `RevokeFamilyAsync` /
>   `RevokeBySubjectAsync` are cleartext-predicate only. Confirmed sound.
>
> **Amendment 2026-07-18 — issue #386 (post-revoke insert completeness): ✅ SIGN-OFF.** Scoped
> *only* to the consume-time family-revoked gate added by this amendment (§11); the three items
> above are unchanged and not re-opened. The fix adds one read-only method (`IsFamilyRevokedAsync`)
> that `TryConsumeAsync`/`FindAsync` consult before honouring a grant's own `Active` status, so a
> successor inserted after a `RevokeFamilyAsync` is caught at *its* redeem, not at write time. No new
> write-path invariant, no two-phase write. Sign-off is conditional on the §11 contract:
> `IsFamilyRevokedAsync` MUST be a strongly-consistent/primary read and MUST throw on fault (never
> catch-and-return-`false`) — a stale-replica or fault-swallowed `false` fails open on reuse
> detection, the same failure class as `FindByHandleAsync`'s fail-closed contract. The bounded,
> attacker-timed residual race (§11, Security Considerations) is accepted, not a gap. The rejected
> insert-time defence-in-depth is explicitly not added (§11, alternatives).
>
> **Amendment 2026-07-18 — issue #388 (zero-row-family revocation sentinel): ⏳ PENDING SECURITY
> REVIEW OF THE IMPLEMENTATION.** Scoped *only* to the revocation-sentinel fix added by this
> amendment (§12); §11 and the three original items are unchanged and not re-opened. The design was
> discussed and approved (architect proposal + security critique) before this write-up; security has
> **not** yet reviewed the shipped code, so this entry is **not** a sign-off. §12 closes the gap §11's
> "familyId always comes from an existing row" assumption leaves open: an auth-code replayed *before*
> its first refresh token is stored lets `RevokeFamilyAsync` run against a zero-row family and leave no
> trace for the §11 gate. The fix has `RevokeFamilyAsync` unconditionally insert one durable, `Revoked`
> revocation-sentinel row keyed deterministically on `familyId`, with `FamilyAbsoluteExpiry` computed
> the same way a real family's is (`ComputeFamilyAbsoluteExpiry`, **not** bounded by the shorter
> auth-code lifetime — an earlier draft that so bounded it failed open, caught in the design critique).
> No new interface method; no public `InsertAsync` contract change (insert-if-absent for the one
> reserved sentinel key is a coordinator-internal helper that, on any insert failure, re-reads via
> `FindByHandleAsync` to confirm the sentinel is genuinely durable before treating the failure as a
> benign self-collision — an earlier draft that swallowed the exception unconditionally would have
> silently masked a genuine transport fault as success, caught in review and fixed before this
> amendment). Review must confirm: the sentinel's expiry is family-scoped (not auth-code-scoped) so it
> outlives any successor; the deterministic key preserves `RevokeFamilyAsync` idempotency with no
> unbounded row growth; the sentinel can never be redeemed (empty payload, `Revoked` status); and the
> confirming `FindByHandleAsync` re-read is itself fail-closed (its own faults propagate, are never
> swallowed).

---

## Context

[ADR 0008](./0008-authorization-code-and-refresh-token-store.md) defined `IRefreshTokenStore` as a
third-party extension point; [ADR 0013](./0013-store-protocol-persistence-split.md) reshaped the
*authorization-code* store down to a dumb, opaque key-value backing primitive
(`IAuthorizationCodeBackingStore`) behind a framework-sealed coordinator, and anticipated the
refresh-token store reusing that same `StoreKey` + backing-KV shape.

Running ADR 0013's KV shape against the refresh-token store's real requirements showed the shared
KV model was **over-unification** for refresh tokens. An authorization code is an ephemeral,
single-use, self-contained blob: the only decision it drives is "redeemed or not," which a dumb
insert-if-absent tombstone answers. A refresh token is a *richer, long-lived, addressable* entity —
it belongs to a rotation **family** and to a **subject**, and its security-critical operations are
**revocation by family** (RFC 9700 §4.13, on reuse detection) and, prospectively, **revocation by
subject** (logout-all). Those are queries: `UPDATE ... SET status = Revoked WHERE family_id = @f`
and `... WHERE subject = @s`.

A dumb opaque KV cannot express those predicates. Backing them on a KV forces the machinery ADR
0013's parked refresh-token draft accreted *solely because the KV could not query*: a write-once
per-family metadata record, an enumeration-free family-revocation *marker* keyed on `Hash(FamilyId)`
whose TTL had to be sized from only a `familyId`, a four-namespace key layout, a second
`TryInsertAsync` on every store, and two `Unprotect` catch sites with opposite semantics. Every one
of those exists to work around the missing `WHERE`.

The reshape is therefore to make the refresh-token store a **queryable persisted-grant store** — the
model Duende IdentityServer (`IPersistedGrantStore`) and OpenIddict use — while the framework-sealed
coordinator keeps owning all protocol. **Going queryable removes machinery, it does not add it:**
family metadata becomes a plain column, family/subject revocation becomes a direct bulk `UPDATE`,
the marker/TTL-sizing problem disappears, the two per-store writes collapse to one, and one of the
two `Unprotect` catch sites disappears because reuse/revoke/mismatch/expiry are now decided from
cleartext columns before anything is decrypted.

The price, paid honestly: the store now requires equality-query + bulk-update-by-predicate.
Relational SQL and Cosmos give that natively; **Redis does not** — a hand-rolled Redis backend must
maintain secondary indexes whose non-transactional drift silently breaks family revocation, which is
exactly the dual-write the maintainer rejected. So this store is **relational-first**, and Redis is
supported (if wanted) via a framework-owned adapter, not sanctioned as a newcomer DIY (§8).

Nothing is published yet (pre-1.0, see `CONTRIBUTING.md`), so the cost of diverging the extension
point now is this ADR plus a re-parenting of the first-party refresh-token store — the cost of
forcing refresh tokens onto the code store's KV shape is a permanent public API that carries the
marker/dual-write machinery forever.

---

## Current State

### 1. Divergence: a queryable grant store, not the code store's opaque KV

The refresh-token store deliberately does **not** reuse `IAuthorizationCodeBackingStore`. Its
extension point is a *different interface type* — `IRefreshTokenGrantStore` — that stores a
**structured row with cleartext, queryable, non-secret columns** plus one Data-Protection-encrypted
payload, rather than a single opaque byte blob. This is the core reason the code store's shape does
not transfer: refresh-token revocation, reuse, and expiry decisions must be **predicates over live
rows** (`UPDATE ... WHERE family_id = X`), and that cannot be derived from a single encrypted blob.
This is consistent with ADR 0013's already-recorded rejection of a single shared backing interface
for both stores (0013's "single shared backing interface" alternative) — the two stores diverge on
lifetime, durability pressure, and now *addressability*.

Everything protocol-critical still lives in the framework-sealed coordinator (see §4). "Grant" ties
the interface to the established persisted-grant terminology the divergence is modelled on.

### 2. `RefreshTokenGrant` — cleartext queryable columns + one encrypted payload

One structured row. Cleartext, non-secret, queryable columns on the outside; the sensitive token
metadata sealed inside one Data-Protection blob the backend stores verbatim and never interprets.

```csharp
namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// One persisted refresh-token grant row, as seen by a persistence backend. The framework
/// constructs and consumes these; a backend only stores, retrieves, and runs equality queries over
/// them. The columns above <see cref="ProtectedPayload"/> are non-secret and queryable; the payload
/// is opaque Data-Protection ciphertext a backend MUST store verbatim and never interpret.
/// </summary>
public sealed record RefreshTokenGrant
{
    /// <summary>Primary key: the framework's SHA-256 hash of the raw handle. Never the raw handle.</summary>
    public required StoreKey HandleHash { get; init; }        // StoreKey reused from ADR 0013 §2

    /// <summary>Queryable. Cleartext, non-secret random GUID shared across a rotation chain. Index this.</summary>
    public required string FamilyId { get; init; }

    /// <summary>Queryable. Cleartext subject identifier (PII, not a bearer credential). NOT a
    /// <see cref="StoreKey"/>: it is honest cleartext, not opaque-already-hashed. Protected by
    /// DB access control + encryption at rest, the Duende/OpenIddict posture (see Security
    /// Considerations). Index this.</summary>
    public required string Subject { get; init; }

    /// <summary>Queryable. Cleartext client_id (public, not secret) the grant is bound to.</summary>
    public required string ClientId { get; init; }

    /// <summary>Queryable, non-secret. Absolute wall-clock the whole family expires at; drives cleanup.</summary>
    public required DateTimeOffset FamilyAbsoluteExpiry { get; init; }

    /// <summary>Queryable, non-secret. This token's logical expiry (coordinator applies accept-grace skew).</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Queryable, non-secret. Lifecycle state. The single-use pivot is a CAS on this column.</summary>
    public required RefreshGrantStatus Status { get; init; }

    /// <summary>Opaque Data-Protection ciphertext of the serialized <see cref="RefreshTokenEntry"/>.
    /// Store verbatim. A backend can never read the sub/scope/session claims inside it.</summary>
    public required ReadOnlyMemory<byte> ProtectedPayload { get; init; }
}

/// <summary>Lifecycle state of a persisted refresh-token grant.</summary>
public enum RefreshGrantStatus
{
    /// <summary>Live and consumable.</summary>
    Active = 0,
    /// <summary>Consumed exactly once (its rotated successor was issued). Presenting it again is reuse.</summary>
    Consumed = 1,
    /// <summary>Its family was revoked. A still-live token in the family reads as this.</summary>
    Revoked = 2,
}
```

`HandleHash` is a `StoreKey` (ADR 0013 §2), whose constructor is framework-only, so a backend can
never fabricate one from a raw handle: "hash before you key" is **structurally unrepresentable in
third-party code**. `Subject` is deliberately **not** a `StoreKey` — that type means "opaque,
already-hashed" (ADR 0013 §2), and reusing it for a cleartext PII column would misrepresent what the
column is. The subject is stored as an honest cleartext `string`; it is not a bearer credential, and
its confidentiality rests on infrastructure-layer controls (DB access control, encryption at rest,
PII policy), the same posture Duende IdentityServer and OpenIddict take for their subject columns and
the same posture this ADR already accepts for cleartext `FamilyId` (see Security Considerations).
`FamilyId` likewise stays a cleartext `string` because the settled DP-key-rotation-survival
requirement mandates it be recoverable *without* decryption, and it is a non-secret GUID (§7).

### 3. `IRefreshTokenGrantStore` — six methods, one atomicity invariant

> **Amended by issue #386 (2026-07-18).** A sixth method, `IsFamilyRevokedAsync`, was added — see
> the method comment below and §11. It is a **read-only equality query**, not a new write-path
> invariant, so it does not reopen the over-unification the Context section rejects: the interface
> still owns no protocol, no state machine beyond the one CAS, no outcome selection. The "exactly
> five methods" framing below now reads as six; the reasoning for keeping the surface minimal (no
> bulk remove, no bulk-read-by-family/subject) is unchanged.

```csharp
namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// The persistence extension point for refresh-token grants. Implement this to store grants in SQL,
/// Cosmos, etc. It owns NO protocol: no hashing (keys arrive pre-hashed as <see cref="StoreKey"/>),
/// no encryption (payloads arrive as ciphertext), no single-use state machine beyond the ONE atomic
/// invariant on <see cref="TryMarkConsumedAsync"/>, no expiry logic, no outcome selection. It stores
/// rows and runs equality queries over their non-secret columns. Native exceptions may propagate
/// freely; the coordinator's Guarded wrapper (ADR 0013 §8) maps them to ZeeKayDaStoreException.
/// </summary>
public interface IRefreshTokenGrantStore
{
    /// <summary>Insert a new grant. The handle is 256-bit random, so a primary-key collision is a
    /// genuine duplicate/bug — let the unique-constraint violation propagate (the coordinator wraps it).</summary>
    ValueTask InsertAsync(RefreshTokenGrant grant, CancellationToken ct);

    /// <summary>Return the grant for <paramref name="handleHash"/>, or null ONLY if confirmed absent.
    /// Read-only. Fail-closed: on ANY transport/backend fault you MUST let the exception propagate —
    /// you MUST NOT catch it and return null (a fault masked as null is read as "no such token" and
    /// silently defeats reuse detection). Same fail-closed contract as ADR 0013 §3's GetAsync.</summary>
    ValueTask<RefreshTokenGrant?> FindByHandleAsync(StoreKey handleHash, CancellationToken ct);

    /// <summary>THE atomic invariant. Transition the grant at <paramref name="handleHash"/> from
    /// Active to Consumed as a SINGLE atomic operation, and return whether THIS call performed the
    /// transition: true iff the row was Active and is now Consumed because of this call; false if the
    /// row was not Active (already Consumed or Revoked) or is absent.
    /// SQL: UPDATE ... SET status=Consumed WHERE handle=@h AND status=Active; return rowsAffected==1.
    /// Cosmos: conditional replace with IfMatch=etag. Redis: a Lua script / WATCH-MULTI-EXEC on the key.
    /// If this is NOT atomic, single-use enforcement is lost (two consumers both transition it).</summary>
    ValueTask<bool> TryMarkConsumedAsync(StoreKey handleHash, CancellationToken ct);

    /// <summary>Set Status=Revoked for EVERY grant whose FamilyId == <paramref name="familyId"/>.
    /// Idempotent. Correctness bar is COMPLETENESS — every grant in the family, including still-live
    /// and any inserted mid-revoke, MUST end up Revoked (RFC 9700 §4.13). Mark, do not delete: a
    /// still-live token in the family must remain findable and read as Revoked.</summary>
    ValueTask RevokeFamilyAsync(string familyId, CancellationToken ct);

    /// <summary>Set Status=Revoked for EVERY grant whose Subject == <paramref name="subject"/>.
    /// Same completeness bar as RevokeFamilyAsync. Present so a FUTURE subject-level logout-all is
    /// possible; the endpoint is deferred and no coordinator method calls this yet (§6). The subject
    /// arrives as cleartext (it is a plain equality predicate, not a keyed lookup) — this control
    /// must never fail to match, which is why the subject is not peppered/keyed (§ item 1).</summary>
    ValueTask RevokeBySubjectAsync(string subject, CancellationToken ct);

    /// <summary>Return true if ANY grant whose FamilyId == <paramref name="familyId"/> currently
    /// reads Revoked. Read-only, no side effects (issue #386, §11). The coordinator calls this before
    /// honouring a grant's own Active status, so a successor inserted after RevokeFamilyAsync is
    /// caught at consume time. MUST be a strongly-consistent / primary read (a stale-replica read that
    /// misses a just-committed revoke fails open) and MUST throw on fault — you MUST NOT
    /// catch-and-return false (false reads as "not revoked" and defeats the gate). Same fail-closed
    /// tier as FindByHandleAsync. SQL: SELECT EXISTS(SELECT 1 FROM grants WHERE family_id=@f AND
    /// status=Revoked).</summary>
    ValueTask<bool> IsFamilyRevokedAsync(string familyId, CancellationToken ct);
}
```

The single hard invariant is the **compare-and-set on `Status`** in `TryMarkConsumedAsync` — read
`Active` and write `Consumed` indivisibly, reporting whether this call did it. This is the
refresh-token analogue of ADR 0013's insert-if-absent invariant, but a *different primitive*: a CAS
on an existing row, not an insert-if-absent of a new one.

**Deliberately absent from the interface:**

- **No `Remove` on the hot path.** Consume *marks*, it does not delete — the consumed row is the
  reuse tombstone (§5). Expired-row cleanup is a maintenance concern, not coordinator protocol:
  Cosmos/Redis self-clean via native per-item TTL sized from `FamilyAbsoluteExpiry`; relational
  ships a first-party sweep job. A cleanup method can be added compatibly later if wanted; keeping
  it off the extension point keeps the newcomer's surface to five obvious methods.
- **No bulk `SELECT`-by-family / by-subject that returns grants.** The coordinator never needs to
  *read* a whole family or subject — it needs to *revoke* them. A bulk-read would be a needless
  enumeration/leak surface. The by-family / by-subject capability is expressed only as the
  bulk-revoke predicate, which is all logout-all requires.

### 4. Coordinator ↔ store, sealing, and the consume flow

`IRefreshTokenStore` stays the framework-sealed coordinator the endpoints depend on and inject; its
public method surface (`StoreAsync`, `FindAsync`, `TryConsumeAsync`, `RevokeFamilyAsync`) is
**unchanged** for callers. It is sealed the **same way** ADR 0013 §1 seals `IAuthorizationCodeStore`
— a `public` interface (so `ZeeKayDa.Auth.AspNetCore` can inject it cross-assembly) with an
`internal` member only friend assemblies can satisfy, so a hand-rolled protocol store is a compile
error. See ADR 0013 §1; not re-derived here. Internally the sealed `RefreshTokenStore` now delegates
to `IRefreshTokenGrantStore` (was `IRefreshTokenKeyValueStore`). `H(x) = Base64Url(SHA-256(UTF8(x)))`,
performed by the framework.

**`StoreAsync(handle, entry)` — one insert (the parked KV draft needed two):**

```
key   = StoreKey(H(handle))
entry.ExpiresAt = min(now + RefreshTokenLifetime, entry.FamilyAbsoluteExpiry)   // clamp; sentinel-safe (§5)
grant = new RefreshTokenGrant {
    HandleHash           = key,
    FamilyId             = entry.FamilyId,             // cleartext column
    Subject              = entry.Sub,                  // cleartext PII column (not hashed; see §item 1)
    ClientId             = entry.ClientId,             // cleartext column
    FamilyAbsoluteExpiry = entry.FamilyAbsoluteExpiry, // plain column — no separate metadata record
    ExpiresAt            = entry.ExpiresAt,
    Status               = Active,
    ProtectedPayload     = protect(serialize(entry)),  // only secret material is encrypted
}
Guarded(store.InsertAsync(grant))
```

No per-family metadata record, no second insert, no marker-TTL arithmetic.

**`TryConsumeAsync(handle, clientId)` — cleartext reads, one atomic pivot, one decrypt:**

```
key   = StoreKey(H(handle))
grant = Guarded(store.FindByHandleAsync(key))
if grant is null                                -> NotFound
if grant.Status == Revoked                      -> Revoked{ grant.FamilyId }          // cleartext, no decrypt
if grant.Status == Consumed                     -> AlreadyConsumed{ grant.FamilyId }  // reuse detected; no decrypt
if Guarded(store.IsFamilyRevokedAsync(grant.FamilyId)) -> Revoked{ grant.FamilyId }   // #386 gate (§11): family revoked even if THIS row still reads Active
if now >= grant.ExpiresAt + ClockSkewTolerance  -> NotFound                           // accept-grace expiry (ADR 0013 §6)
if grant.ClientId != clientId                   -> ClientMismatch                     // no consume, no revoke; no decrypt
// single-use pivot — the ONLY correctness-critical atomic op in the whole design:
won = Guarded(store.TryMarkConsumedAsync(key))
if !won:                                                                              // lost the race
    reread = Guarded(store.FindByHandleAsync(key))
    return reread?.Status == Revoked ? Revoked{familyId} : AlreadyConsumed{familyId}
// we won the transition; now — and ONLY now — do we touch ciphertext:
try   { return Consumed{ entry = deserialize(unprotect(grant.ProtectedPayload)) } }
catch (CryptographicException) { return NotFound }                                    // the SINGLE catch site (§7)
```

**Concurrent double-consume resolves to exactly one `Consumed`.** Two requests both read the grant
as `Active` and both call `TryMarkConsumedAsync`. The backend serializes the two conditional writes;
exactly one finds `status = Active` and transitions it (`true`), the other affects zero rows
(`false`), re-reads, and returns `AlreadyConsumed`. Exactly one `Consumed` + one `AlreadyConsumed`,
every time — the same single-winner guarantee as ADR 0013, on a CAS instead of an insert-if-absent.

**`TryConsumeAsync` does NOT self-revoke on reuse detection.** On `Consumed`/`Revoked` it returns
`AlreadyConsumed{FamilyId}` / `Revoked{FamilyId}` and it is the **caller/endpoint's** job to call
`RevokeFamilyAsync` — the settled ADR 0008/0013 contract, kept exactly as-is. Queryability would now
*technically* let the coordinator self-revoke by predicate without the `familyId` round-trip, but
this was considered and rejected (see "Self-revoke inside `TryConsumeAsync`" in the alternatives).

### 5. Absolute family-lifetime cap and mark-don't-delete

- **`AbsoluteFamilyLifetime` option.** `FamilyAbsoluteExpiry` is baked at family birth (first token
  of the family) and **propagated verbatim through every rotation**, so the whole chain shares one
  absolute wall-clock ceiling. Each token's own `ExpiresAt = min(now + RefreshTokenLifetime,
  FamilyAbsoluteExpiry)`. Per-token `RefreshTokenLifetime` **is** the idle window — there is no
  separate idle option.
- **Effectively-infinite escape hatch.** Setting `AbsoluteFamilyLifetime` to the
  `DateTimeOffset.MaxValue` sentinel disables the absolute cap; the framework **warns at startup**
  when this is configured, so an unbounded family lifetime is an explicit, visible opt-in
  (secure-by-default).
- **Mark, don't delete.** Consume and revoke *mutate `Status`*; they never delete the row. A
  still-live token in a revoked family must read as `Revoked`, not `NotFound` — deleting would turn
  a reuse into the wrong (`NotFound`) signal and lose the tombstone. The consumed row is likewise
  the reuse tombstone.
- **Self-clean.** Rows self-expire past `FamilyAbsoluteExpiry`: Cosmos/Redis via native per-item TTL
  from the `FamilyAbsoluteExpiry` column; relational via a periodic first-party sweep
  (`DELETE WHERE family_absolute_expiry < now - skew`). `AbsoluteFamilyLifetime` gives the sweep its
  horizon. Note the sweep's `- skew` margin: a row is only physically removed once it is past the
  absolute cap by more than `ClockSkewTolerance`, so the accept-grace window (§ ADR 0013 §6) never
  needs a tombstone the sweep already deleted — this interaction is flagged for security sign-off
  (banner item 2).

### 6. Family and subject revocation mechanics

**Family revocation** is `RevokeFamilyAsync(familyId)` → `UPDATE grants SET status = Revoked
WHERE family_id = @familyId` (backends may also add `AND status != Revoked`; either is safe, both
`Consumed` and `Revoked` are terminal and block consume). It is **complete by construction** on a
queryable store: it hits every row in the family — past-consumed, currently-live, and there is no
"future token re-stored under the family" case because rotation only happens on a successful
consume, which a revoked family blocks. This replaces the parked KV draft's whole
marker/`fm`-record/TTL-sizing apparatus: revocation is a predicate over rows that already exist, so
there is no revocation horizon to size from a bare `familyId`.

**Subject revocation** is `RevokeBySubjectAsync(subject)` → the identical shape with a different
predicate. It exists on the grant store **now** so a future logout-all is *possible*, but the
endpoint that would call it is **explicitly deferred** — it is not part of #376's build, no
coordinator method invokes it yet, and its presence on the store is a capability, not a shipped
feature. Do not mistake the store column/method for a delivered logout-all.

### 7. One `Unprotect` catch site (contrast: ADR 0013's two)

ADR 0013 §7 has **two** `Unprotect` catch sites with deliberately opposite semantics
(entry-decrypt-fail → `NotFound`; tombstone-decrypt-fail → *still* `AlreadyRedeemed{FamilyId}`), an
asymmetry a refactor could silently collapse, requiring a MUST test pinning both. That asymmetry
existed because the code store had to recover `FamilyId` from a tombstone whose secret part might be
undecryptable after a DP key rotation.

Here, `FamilyId`, `Status`, `ClientId`, and `ExpiresAt` are all **cleartext columns**, so reuse
detection (`Consumed` → `AlreadyConsumed{FamilyId}`), revocation detection (`Revoked` →
`Revoked{FamilyId}`), `ClientMismatch`, and expiry are all decided **without ever decrypting**. The
*only* `Unprotect` call is on the `Consumed` happy path (to hand back the entry), and its only
failure mode is `NotFound`. **One catch site, one semantic.** The two-catch-site invariant — and the
test pinning it — simply ceases to exist. This is a simplification *enabled by queryability*: the
security-relevant decisions no longer ride on decryption at all. (Confirming this does not
reintroduce a fail-open path is security-sign-off item 3.)

### 8. Backends: relational-first; Redis is not first-class

| Backend | Insert | Find-by-handle | CAS consume | Revoke by family / subject | Verdict |
|---|---|---|---|---|---|
| Relational SQL | `INSERT`, PK on handle | `SELECT WHERE handle=@h` | `UPDATE ... WHERE handle=@h AND status=Active`, rows==1 | `UPDATE ... WHERE family_id=@f` (index) | **Native. First-class.** |
| Cosmos DB | `CreateItemAsync` | point read | conditional replace `IfMatch=etag` | query + patch | **Native, correctness-safe; partition-key choice is a perf note only.** |
| Redis | grant key **+ maintain family/subject index sets** | `GET` grant key | Lua / WATCH-MULTI-EXEC | `SMEMBERS` then update each — **only as complete as the index** | **Not native. Secondary-index burden. Not first-class.** |

- **SQL passes the newcomer test cleanly.** The one atomicity invariant is a native single-statement
  atomic CAS under row locking; revocation is a single `UPDATE`, complete by construction. The only
  "remember to" is two indexes (`family_id`, `subject`) — and a *missing* index is a pure
  performance regression: the query still returns the correct rows. Nothing a docs-ignorant author
  plausibly writes here silently breaks a security control.
- **Cosmos: correctness-safe, perf needs a partition-key choice.** Whatever the partition key, the
  queries return the right rows, so correctness holds. Partition-key choice only drives cost
  (partition by `familyId` makes family revocation single-partition and by-subject fan out; by
  `subject` flips it; by `handleHash` fans both out). A newcomer can pick a slow key, never a
  wrong one — so Cosmos passes the newcomer test for correctness with a documented modelling note.
- **Redis is explicitly NOT first-class.** Redis has no `WHERE family_id = X`, so a Redis backend
  must maintain its own `family:{id} → {handles}` and `subject:{subject} → {handles}` secondary index
  sets. That is a **non-transactional dual-write** on every insert: if the grant write and the index
  add are not atomic-together and a crash lands between them, the index drifts — a live grant exists
  that `RevokeFamilyAsync` will never see, i.e. a still-`Active` token in a "revoked" family, a
  **silent reuse window (RFC 9700 §4.13 broken)**. The failure is silent: single-token happy-path
  tests pass; the gap only appears with multi-token families, the rotation path, or a partial-write
  crash. Redis Cluster makes it worse — `MULTI/EXEC`/Lua atomicity requires all keys in one hash
  slot, which a naive author will not hash-tag. This is precisely the dual-write the maintainer
  rejected for the unified KV.

  Per Design Principle 6, the tier-1 fix is to make the index un-get-wrong-able rather than to
  document it: **do not sanction hand-rolled Redis.** The clean queryable `IRefreshTokenGrantStore`
  is the extension point; natively-queryable backends (SQL, Cosmos) implement it directly; and if
  Redis is wanted, the framework ships a **first-party Redis adapter** that owns the secondary-index
  maintenance correctly, once. A third party with a genuinely exotic non-queryable backend *may*
  still implement the interface, inheriting the index-completeness burden, and only *then* reaches
  the tier-3 last resort: the conformance kit (§9).

  **Shipped-status note (added at implementation time, PR #383 review):** the first-party
  `DistributedCacheRefreshTokenGrantStore` this implementation ships over `IDistributedCache` is
  **not** the "first-party Redis adapter that owns the secondary-index maintenance correctly, once"
  described above — `IDistributedCache` has no atomic multi-key primitive, so that adapter cannot
  structurally close the TOCTOU/index-drift gap this section describes; it can only document it
  (which it does, at length, in its type-level remarks). It fills the dev/test convenience slot only.
  The correct, production-grade Redis adapter this section anticipates (Lua scripting or hash-tagged
  `WATCH-MULTI-EXEC`) remains unbuilt. The sanctioned production path today is a natively queryable
  backend (relational SQL or Cosmos).

### 9. Revocation-completeness conformance kit (exotic backends only)

Mirroring ADR 0013 §10's derive-and-run xUnit fixture pattern, the framework ships a conformance kit
for backends that are neither the first-party relational path nor a framework-owned adapter. It is
the **last resort** for invariants the CLR cannot make structurally true, not the sanctioned Redis
path. It exercises:

1. **Revocation completeness (by family)** — insert N grants across one family, `RevokeFamilyAsync`,
   assert **all N** read `Revoked`, **including one inserted mid-revoke** (the race a drifting
   secondary index loses).
2. **Revocation completeness (by subject)** — the same for `RevokeBySubjectAsync`.
3. **CAS atomicity** — a concurrent-consume race proving exactly one of N simultaneous
   `TryMarkConsumedAsync` calls returns `true` (the ADR 0013 §10 atomicity case, ported to the CAS
   primitive).
4. **Fail-closed / throws-not-swallows** — fault injection proving native faults surface as
   `ZeeKayDaStoreException`, and specifically that `FindByHandleAsync` throws (does NOT
   catch-and-return-null) on a transport fault (ADR 0013 §3/§8).
5. **Post-revoke insert completeness (issue #386, §11)** — `RevokeFamilyAsync`, then a grant inserted
   *strictly after* the revoke returns, then assert `IsFamilyRevokedAsync` reports the family revoked
   (i.e. a subsequent consume treats the new grant as dead). This is distinct from case 1's
   concurrent-overlap race. Plus a fail-closed case: `IsFamilyRevokedAsync` throws (does NOT
   catch-and-return `false`) on a transport fault.
6. **`InsertAsync` accepts a born-`Revoked` grant (issue #388, §12)** — insert a grant that is
   `Revoked` from birth with **no prior `Active` row** for its family, then assert
   `IsFamilyRevokedAsync` reports the family revoked. This is the backend-level precondition the
   coordinator's §12 sentinel technique depends on (`InsertAsync` must tolerate a `Revoked`-from-birth
   row, and the family-revoked query must see it). The end-to-end zero-row-family completeness proof —
   `RevokeFamilyAsync` on a family with no rows arming the gate for a later-inserted successor — is a
   *coordinator*-level scenario (the sentinel insert lives in `RefreshTokenStore`, not the backend), so
   it is pinned in `RefreshTokenStoreTests.cs`, not this shared backend conformance kit; a bare
   `IRefreshTokenGrantStore.RevokeFamilyAsync` is still a no-op on zero rows and the kit must not assert
   otherwise.

### 10. Renames and public-type impact

- **Rename** `RefreshTokenConsumptionOutcome` → `RefreshTokenConsumptionResult` (nested cases
  unchanged), for consistency with `AuthorizationCodeRedemptionResult` / `ClientAuthenticationResult`
  / `SigningResult`. Pre-1.0 rename with no compatibility impact.
- **New:** `IRefreshTokenGrantStore`, `RefreshTokenGrant`, `RefreshGrantStatus`.
- **Deleted:** the refresh-token KV marker interface (`IRefreshTokenKeyValueStore`). Refresh tokens
  no longer use the KV primitive; the two extension points are now distinct interface *types*, so
  they are self-describing in IntelliSense without marker interfaces.
- **Kept:** `RefreshTokenEntry` as the decrypted protocol payload the endpoint sees in
  `Consumed.Entry`; it gains `FamilyAbsoluteExpiry`. Its `Scope`, session id, `IssuedAt`, and
  previous-handle-hash stay *inside* `ProtectedPayload`; `FamilyId` / `Subject` / `ClientId` /
  `ExpiresAt` are duplicated up onto `RefreshTokenGrant` as queryable columns (the encrypted copy is
  authoritative for issuance; the columns are for query/expiry/reuse/by-subject-revocation decisions).
  `Sub` therefore now exists both inside `ProtectedPayload` and as the cleartext `Subject` column.
- **Kept, sealed, unchanged public surface:** `IRefreshTokenStore` (coordinator), implemented by
  sealed `RefreshTokenStore`, now composed over `IRefreshTokenGrantStore`. No `RevokeBySubjectAsync`
  coordinator method is added (logout-all deferred, §6).
- Registration idiom: `.AddRefreshTokenGrantStore<SqlRefreshTokenGrantStore>()`, wiring the
  third-party grant store plus the framework's sealed coordinator, exactly as ADR 0013 §4 wires the
  code-store coordinator over its backing store.

### 11. Issue #386 — post-revoke insert completeness (consume-time family-revoked gating)

**The gap.** `RevokeFamilyAsync` / `RevokeBySubjectAsync` mark only rows that exist *when the call
evaluates its predicate*. A grant `InsertAsync`'d into the family **after** (or racing) the revoke
call is never visited by that scan and lands `Active`, fully usable. The exploit (issue #386): two
requests race to redeem `RT0`; the winner's CAS succeeds and it begins issuing successor `RT1` via
`StoreAsync`; the loser detects `AlreadyConsumed{FamilyId}` and calls `RevokeFamilyAsync(familyId)`.
If `RT1`'s insert lands after that revoke returns, `RT1` is a live token in a revoked family — an
RFC 9700 §4.13 completeness hole. §6's "complete by construction" claim held only over rows already
present, not over the family identifier.

**The fix — gate at consume time, not write time.** `InsertAsync` is **untouched**: grants always
insert `Active`, no protocol decision on the write path. A sixth read-only method
`IsFamilyRevokedAsync(familyId)` (§3) reports whether any grant in the family currently reads
`Revoked`. `TryConsumeAsync` (mandatory — it is the successor-minting decision) **and** `FindAsync`
(so introspection never reports a revoked-family grant as live) call it before honouring a grant's
own `Active` status; a revoked family kills the grant regardless of its own row.

This closes the gap because **there is no multi-step write to interrupt**. Every redeem re-derives
family state fresh from what is durably committed *at that instant*, and the tombstone that triggered
the revoke is itself permanent (mark-don't-delete, §5/§6). So insert/revoke ordering and any crash
between them stop mattering: whenever `RT1` is finally presented, the durable `Revoked` sibling is
already there to be seen. `familyId` is only ever obtained from an existing row (e.g.
`AlreadyConsumed{FamilyId}`), so the revoking scan always leaves at least one durable tombstone — no
zero-rows-at-revoke marker is needed.

**Contract (security sign-off conditions).** `IsFamilyRevokedAsync` MUST be a
strongly-consistent / primary read — a stale read-replica that misses a just-committed revoke fails
open. It MUST throw on transport/backend fault and MUST NOT catch-and-return `false` (a
`false`-masked fault reads as "not revoked" and defeats the gate). Same fail-closed tier as
`FindByHandleAsync` (§3). The conformance kit (§9) gains a case: after `RevokeFamilyAsync`, a grant
inserted *strictly after* the revoke returns MUST be reported revoked by a subsequent consume
(distinct from §9's existing concurrent-overlap case), plus a fail-closed fault-propagation case for
`IsFamilyRevokedAsync`.

**Accepted residual (bounded, attacker-timed).** A consume's `IsFamilyRevokedAsync` can pass
microseconds before a concurrent `RevokeFamilyAsync` commits, letting that one consume mint a
successor — which then dies at *its own* next consume, one rotation later. This live-request window is
inherent to every detect-and-revoke design (RFC 9700 §4.13 always has one); it needs active racing,
not a passive failure, and it self-heals in one rotation. Accepted, not a gap.

**What changes for implementers.** Add `IsFamilyRevokedAsync` to the first-party stores and wire the
two coordinator call sites. The "Known gap, tracked separately (issue #386)" `<remarks>` on
`RevokeFamilyAsync` (and the corresponding sentence on `RevokeBySubjectAsync`) in
`src/ZeeKayDa.Auth/Stores/IRefreshTokenGrantStore.cs` are **deleted** — the gap is closed, so the
XML docs must stop describing it as open.

### 12. Issue #388 — revocation of a zero-row family (revocation sentinel)

**The gap.** §11 closes the post-revoke insert race *provided the revoked family has at least one
durable row when `RevokeFamilyAsync` runs* — its last paragraph rests on exactly that: "`familyId` is
only ever obtained from an existing row … so the revoking scan always leaves at least one durable
tombstone — no zero-rows-at-revoke marker is needed." Issue #388 is the case that assumption misses.
An authorization code can be **replayed before its first refresh token is ever stored**: the winner's
CAS on the auth-code store succeeds and it *begins* minting `RT1` via `StoreAsync`, while the loser
detects the replay and calls `RevokeFamilyAsync(familyId)` — but at that instant the family has **zero
rows** (the winner's `StoreAsync` has not yet committed, or is in flight). `RevokeFamilyAsync`'s
`UPDATE … WHERE family_id = @f` matches nothing and leaves no trace. When `RT1`'s insert then lands
`Active`, §11's `IsFamilyRevokedAsync` gate finds **no `Revoked` sibling** to see, and `RT1` is a live
token in a family that was explicitly revoked — the RFC 9700 §4.13 hole reopened one layer down.

**The fix — a durable revocation sentinel.** `RevokeFamilyAsync(familyId)` now **unconditionally**
inserts one additional row — a synthetic *revocation sentinel* — alongside its existing bulk-revoke of
any real pre-existing rows:

- `FamilyId` = the family being revoked; `Status` = `Revoked`.
- `HandleHash` = a **deterministic** key derived from the family id (`H("revocation-sentinel:" +
  familyId)`), **not** a random handle — so repeated `RevokeFamilyAsync` calls for the same family
  always target the same row. A random key would insert a new phantom row every call: unbounded growth
  and a broken idempotency contract (the interface doc comment requires `RevokeFamilyAsync` be
  idempotent).
- `Subject` / `ClientId` = fixed, clearly-reserved sentinel constants, documented as the
  revocation-marker sentinel — **not** real subject/client data, chosen so they cannot collide with
  real values.
- `ProtectedPayload` = empty. A sentinel row is `Revoked`, so it never reaches the `Unprotect` happy
  path (§4/§7); it is a marker, never a redeemable grant.
- `FamilyAbsoluteExpiry` = computed **the same way a real family's expiry is computed** —
  `TokenEndpointOptions.ComputeFamilyAbsoluteExpiry(now)` (the sentinel-safe helper against the
  `TimeSpan.MaxValue` overflow case, added in PR #383), fed by
  `AuthorizationServerOptions.TokenEndpoint.AbsoluteFamilyLifetime`, which `RefreshTokenStore` already
  has injected via `IOptions<AuthorizationServerOptions>`. This is **not** endpoint-supplied and
  **not** bounded by the (much shorter) auth-code lifetime: a short-lived sentinel would be swept (§5)
  before a genuinely-inserted successor's own, much longer, lifetime ends, silently reopening the very
  gap this section closes.

Now `RevokeFamilyAsync` leaves a durable `Revoked` row for the family **whether or not any real row
existed at call time**, so §11's gate arms unconditionally: whenever `RT1` is finally presented, the
sentinel is already there for `IsFamilyRevokedAsync` to find.

**Why unconditional, not conditional-on-empty-family.** A "only insert the sentinel if the family has
no rows" check needs a family-existence read the six-method interface deliberately does not offer (§3
rejects bulk-read-by-family), and a check-then-insert is itself TOCTOU-shaped against a concurrent
`StoreAsync`. Unconditional costs one extra write on a cold, rare path (revocation) and needs **no new
interface surface**.

**Insert-if-absent for the one reserved key.** `InsertAsync`'s contract still throws on any
`HandleHash` collision — "the handle is 256-bit random, so a collision is a genuine duplicate/bug"
(§3), and that stays true for every real grant. The sentinel deliberately reuses one deterministic key
across repeated revokes, so the sentinel-insert step alone needs **insert-if-absent** semantics. This
is achieved **without changing the public `InsertAsync` contract**: the coordinator owns the sentinel
key format entirely, so a collision on *that* key is provably the coordinator's own prior sentinel —
expected and benign — and is distinguishable from a genuine random-handle collision. **The coordinator
does not infer this from the exception alone.** `Guarded` (§8) flattens every native fault into the
same `ZeeKayDaStoreException` type, so a genuine transport/database fault on the sentinel insert would
be indistinguishable from a benign self-collision by exception shape. Instead, on any exception from the
sentinel `InsertAsync`, the coordinator re-reads the sentinel's key via `FindByHandleAsync` to confirm
the row is *actually* durably present and `Revoked` before treating the failure as benign; if the
confirming read shows the sentinel is genuinely absent (or the read itself throws), the original
exception propagates instead of being swallowed — `RevokeFamilyAsync` must never return successfully
while the sentinel isn't confirmed durable. Every other collision (any real grant's random handle)
still propagates as the duplicate/bug it is; `InsertAsync` as third parties implement it is untouched.

**Crash-safety.** Unlike the §11-rejected insert-then-verify-then-revoke candidate, this has no
multi-step write to interrupt: step 1 (insert the sentinel) is **self-sufficient**.
`IsFamilyRevokedAsync` returns `true` the moment the sentinel exists, arming the gate for the whole
family regardless of whether the bulk-revoke of any pre-existing rows has run yet, and regardless of a
crash between the two. The sentinel is durable (mark-don't-delete, §5) until it self-cleans past the
family's absolute expiry — i.e. after every token the family could ever mint has itself expired.

**What changes for implementers.** Nothing changes in any backend. No new interface method, no
`InsertAsync` contract change, and **no per-backend code** — the entire fix lives in the framework
coordinator (`RefreshTokenStore.RevokeFamilyAsync` in `RefreshTokenStore.cs`), which composes the two
grant-store primitives that already exist: it first calls `_grantStore.InsertAsync(sentinel)` to insert
the sentinel, then the existing `_grantStore.RevokeFamilyAsync(familyId)` for the bulk mark. Sentinel
construction — the deterministic `HandleHash` (`H("revocation-sentinel:" + familyId)`), the reserved
`Subject`/`ClientId` constant, the empty payload, the `Revoked` status, and the `FamilyAbsoluteExpiry`
from `ComputeFamilyAbsoluteExpiry` — is all **protocol**, so it belongs in the coordinator, not smeared
into each persistence backend; this placement follows ADR 0014's "coordinator owns protocol, backend
owns persistence" split and covers every backend, including future third-party ones, for free. The
insert-if-absent self-collision catch is a coordinator-internal `try/catch` scoped to only the sentinel
`InsertAsync` call, so `InsertAsync`'s throw-on-collision contract is untouched for every real grant.
The conformance kit (§9) gains a zero-row-family case: `RevokeFamilyAsync` on a family with no rows,
then a grant inserted into that family, then assert `IsFamilyRevokedAsync` reports it revoked.

---

## Considered and Rejected Alternatives

### Self-revoke inside `TryConsumeAsync` on reuse detection

The issue's open question. Because the store is queryable, the coordinator already holds `FamilyId`
at reuse-detection time and *could* call `RevokeFamilyAsync` on itself with no round-trip, making
reuse-triggered family revocation automatic. **Decided: NO** — `TryConsumeAsync` stays narrow and
does not self-revoke. Two reasons:

1. **It only covers one of the two replay triggers.** Reuse can be detected by *this* coordinator
   (a replayed refresh token) **or** by the separate `AuthorizationCodeStore.TryRedeemAsync`
   coordinator (a replayed authorization code). The auth-code coordinator has no reference to the
   refresh-token coordinator — they are independently registered, swappable stores, and coupling
   them would break that independence. So self-revoke inside `RefreshTokenStore` would auto-revoke
   for one trigger while the other stayed a manual "the caller must remember to call
   `RevokeFamilyAsync`" step — an inconsistent, surprising asymmetry for anyone calling either
   coordinator directly (e.g. a custom endpoint).
2. **It breaks the honesty of the method's name/contract.** "Try to consume" silently gaining a
   side effect that revokes an entire token family is exactly the kind of hidden behaviour, not
   discoverable without reading deep into the implementation, that Design Principle 6 ("docs are not
   a mitigation") and this redesign are built to avoid.

The decided approach instead keeps `TryConsumeAsync` behaving exactly as today (returns
`AlreadyConsumed{FamilyId}` on replay; the caller/endpoint separately calls `RevokeFamilyAsync`).
Sequencing "consume/redeem → inspect outcome → revoke family on replay" **consistently for both
triggers** is the job of a future, per-endpoint abstraction layer — introduced when each relevant
endpoint (token, revocation #105, introspection #101, JWKS #204) is actually built, each deciding
its own abstraction shape at that point. This is a forward pointer only; that layer is explicitly
**out of scope here** and deliberately not a single monolithic cross-cutting orchestration layer.

### Reuse `IAuthorizationCodeBackingStore` / a single shared backing interface

Back refresh tokens on the code store's opaque KV primitive (or a shared base). Rejected: refresh
tokens need revocation/reuse/expiry as **predicates over live rows** (`WHERE family_id = X`), which
a single opaque blob cannot express. Backing that on a KV forces a per-family metadata record, an
enumeration-free revocation *marker*, marker-TTL sizing from a bare `familyId`, a four-namespace key
layout, and two `Unprotect` catch sites — all machinery that exists solely to work around the
missing `WHERE`. The queryable grant store deletes all of it. This is consistent with, and the
concrete realisation of, ADR 0013's already-recorded rejection of a single shared backing interface
(the two stores diverge on lifetime, durability pressure, and addressability).

### Sanction hand-rolled Redis behind documentation

Keep Redis a first-class newcomer target and document the secondary-index requirement. Rejected as a
Design-Principle-6 failure: every trap (missing index, non-atomic dual-write, cross-slot Cluster
atomicity, partial-write drift) **compiles, passes a single-token happy-path test, and silently
breaks family revocation** — a documented invariant a naive implementation violates while looking
correct. The tier-1 fix (make the wrong thing unrepresentable) is available: keep the clean
queryable interface as the extension point and ship a framework-owned Redis adapter that owns the
index maintenance once, rather than asking each Redis author to re-derive it. Hand-rolled Redis is
therefore not sanctioned; exotic non-queryable backends fall to the tier-3 conformance kit (§9).

### Delete-on-consume / delete-on-revoke instead of mark

Delete the row when consumed or when its family is revoked. Rejected: a still-live token in a
revoked family, or a replayed consumed token, must read as `Revoked` / `AlreadyConsumed` so reuse
is detected and the family stays revocable — deleting turns that into `NotFound`, the wrong signal,
and loses the tombstone. Mark-don't-delete keeps the tombstone until it self-cleans past the
absolute family expiry (§5).

### Expose a bulk `SELECT`-by-family / by-subject on the interface

Add read methods returning all grants in a family or for a subject. Rejected: the coordinator never
needs to read a whole family/subject, only to revoke them, and a bulk-read is a needless
enumeration/leak surface on the extension point. The capability is expressed purely as the
bulk-revoke predicate — all logout-all requires.

### Add `RevokeBySubjectAsync` to the coordinator and ship logout-all now

Wire the subject-revocation capability all the way up to a coordinator method and an endpoint.
Rejected as scope creep for #376: the store-level capability is cheap and future-proofing to include
now, but the endpoint (session model, auth, audit, RP-initiated-logout semantics) is a separate
design deferred to its own issue. The store supports the predicate; nothing calls it yet, and the
ADR says so plainly so the capability is not mistaken for a shipped feature.

### Insert-time born-`Revoked` gate (issue #386 Candidate 1)

Have `InsertAsync` decide `Active`-vs-`Revoked` itself via a cross-row conditional write (e.g.
`INSERT ... status = CASE WHEN EXISTS(family_id=@f AND status=Revoked) THEN Revoked ELSE Active`).
Rejected: it puts a **protocol decision on the write path of the extension point third parties
implement directly** (there is no backing-store split for refresh tokens — `IRefreshTokenGrantStore`
*is* what SQL/Cosmos authors write), and it is a *second, harder* atomic invariant on top of the
`TryMarkConsumedAsync` CAS. The CAS is single-key; this is a multi-row predicate-plus-write that only
serialises correctly against a concurrent `RevokeFamilyAsync` under SERIALIZABLE or an explicit
family lock. Under READ COMMITTED it compiles, passes the happy path, and silently leaks the race —
exactly the "newcomer footgun" §8 already warns against. Consume-time gating (§11) needs no write-path
invariant at all.

### Insert-then-verify-then-revoke at the coordinator (issue #386, considered)

Coordinator inserts the successor `Active`, then reads family state, then re-revokes it if the family
turns out revoked. Rejected: a **two-phase write with no compensating action**. A crash or connection
loss between the insert and the verify/re-revoke leaves the successor permanently `Active` in a
revoked family with nothing that will ever retry the fixup — an unbounded durability gap, worse than
the original bug because it needs no concurrency at all. §11's consume-time gate has no write sequence
to interrupt.

### Insert-time "best-effort" born-`Revoked` as defence-in-depth alongside §11

Keep §11's consume-time gate *and* also add a best-effort family-revoked check in `InsertAsync`.
Rejected as a **false-confidence control**: it reintroduces the exact backend-coupling and
isolation-level fragility the two alternatives above were rejected for, to cover a case consume-time
gating already covers **completely** (a successor is caught at its own redeem regardless of insert
ordering). A second, weaker check that can only ever agree with the authoritative one adds surface and
implies a robustness it does not provide. One gate, at consume time, is the whole design.

### A separate `revoked_families` marker table (issue #388)

Record zero-row-family revocations in a dedicated side table (`revoked_families(family_id, expiry)`)
that `IsFamilyRevokedAsync` also consults. Rejected: functionally equivalent to the sentinel row, but
it adds a whole new table/index/TTL concept back onto the extension point — precisely the
marker/metadata machinery this ADR's original redesign *removed* (Context; §6). §12's sentinel reuses
the existing grant-row shape and the existing `IsFamilyRevokedAsync`/`RevokeFamilyAsync` mechanism
verbatim, with no new interface surface and no second storage concept for an implementer to get wrong.

### Endpoint-side sequencing — don't revoke until an RT is confirmed stored (issue #388)

Have the endpoint defer `RevokeFamilyAsync` until a refresh token for the family is confirmed to
exist, so the family is never revoked while it has zero rows. Rejected as insufficient alone: it cannot
observe an **in-flight, not-yet-committed** `StoreAsync` (the winner's `RT1` write may be seconds from
committing when the loser must decide to revoke), so the zero-row window is real regardless of endpoint
ordering. Worse, waiting-to-revoke would *weaken* the RFC 9700 §4.13 code-interception defence this
revoke path exists to serve — the revoke must fire immediately on replay detection, not be gated on a
successor's durability. The sentinel makes revocation correct *whenever* it fires, which is the
property actually needed.

### Bound the sentinel's expiry by the auth-code lifetime (issue #388, earlier draft)

An earlier draft of §12 sized the sentinel's `FamilyAbsoluteExpiry` from the (short) auth-code
lifetime — reasoning that the race only exists around auth-code redemption. Rejected (caught in the
design critique): traced through the actual timeline, a sentinel that expires on the auth-code horizon
is **swept (§5) while a genuinely-inserted successor's own, much longer, family lifetime is still
running**, so `IsFamilyRevokedAsync` stops finding it and the family silently un-revokes — failing
open exactly when it matters. The sentinel must share the *family's* absolute expiry
(`ComputeFamilyAbsoluteExpiry`), so it outlives every token the family could ever mint.

### A random per-call sentinel key (issue #388)

Give each `RevokeFamilyAsync` call a fresh random sentinel handle. Rejected: it breaks
`RevokeFamilyAsync`'s idempotency contract (§3) and causes **unbounded row growth** — every repeated
revoke of the same family inserts another phantom `Revoked` row. The deterministic
`H("revocation-sentinel:" + familyId)` key makes repeated revokes converge on one row (insert-if-absent
against itself), which is what keeps the operation idempotent and bounded.

---

## Consequences

### Positive

- Family and subject revocation become one bulk `UPDATE` by predicate, **complete by construction**
  on a queryable store. The parked KV draft's per-family metadata record, revocation marker,
  marker-TTL/horizon-sizing problem, second per-store insert, and four-namespace layout all
  disappear.
- One of ADR 0013's two `Unprotect` catch sites disappears (§7): reuse/revoke/mismatch/expiry are
  decided from cleartext columns, so decryption only matters on the `Consumed` happy path — fewer
  invariants a refactor can silently break.
- The one atomic invariant is an equally-simple compare-and-set on one row's `Status`, natively
  provided by relational row locking, Cosmos ETag, or a Redis Lua script.
- SQL passes the newcomer test cleanly; Cosmos passes for correctness with a perf note. The residual
  correctness burden is concentrated in exactly one place (non-queryable backends' secondary
  indexes) and handled by keeping it off the newcomer path, not smeared across the interface.

### Negative / Trade-offs

- **Larger cleartext surface than ADR 0013.** Six non-secret columns are stored in clear (vs. 0013's
  single plaintext `FamilyId`), and — because refresh tokens live for months, not
  seconds-to-minutes — they sit at rest far longer. The cleartext `Subject` column in particular is a
  stable, long-lived identifier recurring across many families, so its at-rest correlation profile
  differs from a per-family random GUID, and it moves the subject from ADR 0008's encrypted-payload-only
  treatment into an additional cleartext queryable column (the necessary cost of by-subject
  revocation as a SQL predicate). Assessed and signed off (banner item 1): the subject is PII, not a
  bearer credential, and is protected at the infrastructure layer, matching Duende/OpenIddict.
- **Relational-first, not backend-agnostic.** The store now *requires* equality-query +
  bulk-update-by-predicate, so Redis (and any non-queryable backend) is no longer a first-class DIY
  target — it needs a framework-owned adapter or the conformance kit. This is a deliberate narrowing
  vs. ADR 0013's "any KV works."
- **The CAS atomicity invariant is irreducible.** The CLR cannot prove a given backend's
  `TryMarkConsumedAsync` is atomic — the honest ceiling, mitigated by the mapping guidance and the
  conformance kit (§9), same shape as ADR 0013's insert-if-absent ceiling.
- **One extra write per revocation (issue #388).** `RevokeFamilyAsync` now always inserts a
  revocation-sentinel row in addition to its bulk mark, so every family revocation costs one more write
  than before. Revocation is a cold, rare, reuse-triggered path, and the write is idempotent
  (deterministic key), so this is accepted as the cost of closing the zero-row-family gap without a new
  interface method or a second storage concept (§12).
- **Pre-publication blast radius.** New `IRefreshTokenGrantStore` / `RefreshTokenGrant` /
  `RefreshGrantStatus`; deletes the refresh-token KV marker; renames the consumption outcome type;
  rewrites the first-party refresh-token store as a thin grant-store adapter. Endpoint callers are
  unaffected. Acceptable pre-1.0.

---

## Security Considerations

- **Cleartext queryable columns, including `Subject` (sign-off item 1 — SIGNED OFF).** `FamilyId`,
  `Subject`, `ClientId`, `FamilyAbsoluteExpiry`, `ExpiresAt`, `Status` are non-secret and stored in
  clear so revocation, reuse, mismatch, and expiry are decidable as predicates without decryption.
  None is a bearer credential. The raw handle never reaches the store (it arrives as a `StoreKey`
  hash whose 256-bit random preimage resists reversal). The **subject is stored as honest cleartext**,
  not a hash: a bare SHA-256 over a guessable, low-entropy subject (sequential ids, emails) is
  reversible by rainbow table for the very read-only-DB attacker in scope, so it would provide false
  confidence, not confidentiality — and an HMAC-with-pepper alternative was rejected because
  `RevokeBySubjectAsync` is a control that must never fail to match, which pepper rotation would
  silently break. This is the posture of both reference implementations the store is modelled on
  (Duende `PersistedGrant.SubjectId`, OpenIddict `OpenIddictToken.Subject` — both plain columns; only
  the token *handle* is hashed). The subject is therefore protected as PII by **database-level access
  control (least-privilege roles), encryption at rest (disk/backend-level), and standard PII-handling
  policy over the grant table** — infrastructure-layer controls, exactly as for cleartext `FamilyId`.
- **Residual subject-correlation risk (accepted).** Because `Subject` is deterministic and queryable,
  a read-only store observer can see that N families share one subject and correlate a user's grants
  across families over months — a wider correlation scope than `FamilyId`'s per-chain scope. This is
  intrinsic to having a queryable subject column at all (the price of by-subject revocation); it was
  never closed by the previously-proposed hash (which was itself deterministic), and cleartext does
  not widen it. Accepted as the cost of the capability. A read-only observer of this column set learns
  only which client and subject a grant binds, its lifecycle state, and its expiries — no bearer
  credential and no token-redeemable material.
- **Mark-don't-delete + absolute cap vs. accept-grace (sign-off item 2).** Consumed/revoked rows are
  retained as tombstones until swept past `FamilyAbsoluteExpiry - skew` (§5). Review must confirm the
  clamp `ExpiresAt = min(now + RefreshTokenLifetime, FamilyAbsoluteExpiry)`, the accept-grace window
  (`now >= ExpiresAt + ClockSkewTolerance`, ADR 0013 §6), and the sweep margin do not combine into a
  window where a token is honoured past the family's absolute cap, or where a tombstone is swept
  while still needed for reuse detection.
- **Single `Unprotect` catch site (sign-off item 3).** Reuse and revocation detection read cleartext
  columns and never decrypt; the only `Unprotect` is on the `Consumed` happy path, failing to
  `NotFound`. Review must confirm this does not reintroduce a fail-open path ADR 0013's two-site
  design guarded against — i.e. that no security decision depends on a successful decrypt.
- **Single-use enforcement (RFC 9700 §2.1.1)** rides entirely on the atomic CAS in
  `TryMarkConsumedAsync`; the coordinator owns the state machine, not the implementer.
- **Family revocation completeness (RFC 9700 §4.13)** is complete by construction on a queryable
  store (§6). The one way to break it — a drifting secondary index on a non-queryable backend — is
  kept off the sanctioned path (§8) and pinned by the conformance kit's mid-revoke-insert case (§9).
- **Post-revoke insert completeness (issue #386, §11).** A successor inserted after a
  `RevokeFamilyAsync` returns is caught at *its own* consume by the `IsFamilyRevokedAsync` gate, not
  left `Active`. The gate is fail-closed (strongly-consistent read, throws-not-swallows — §11); a
  stale-replica or fault-swallowed `false` reads as "not revoked" and fails open, which the contract
  and conformance kit (§9 case 5) forbid. The bounded, attacker-timed live-request race that remains
  (a consume passing microseconds before a concurrent revoke commits) self-heals in one rotation and
  is accepted, not a gap — inherent to any RFC 9700 §4.13 detect-and-revoke flow.
- **Zero-row-family revocation completeness (issue #388, §12).** A family revoked while it holds zero
  rows — an auth-code replayed before its first refresh token is stored — would otherwise leave no
  trace for the §11 `IsFamilyRevokedAsync` gate, and a later-inserted successor would read `Active`.
  `RevokeFamilyAsync` now unconditionally inserts a durable, deterministic-keyed, `Revoked` revocation
  sentinel whose `FamilyAbsoluteExpiry` is family-scoped (not auth-code-scoped), so the gate arms even
  for a zero-row family and stays armed until every token the family could mint has expired. The
  sentinel carries no `ProtectedPayload` and is `Revoked`, so it is never redeemable. **Pending
  security review of the shipped implementation** (banner); the design was reviewed and approved
  pre-implementation.
- **Fail-closed I/O** is the shared obligation from ADR 0013 §8, unchanged: the framework's
  `Guarded(...)` wraps thrown faults as `ZeeKayDaStoreException` and rethrows
  `OperationCanceledException` unwrapped, while `FindByHandleAsync`'s contract forbids
  catch-and-return-null (a fault-masked-as-absent read fails open on reuse detection).
- **Handle confidentiality:** the raw handle never reaches the store; only its `StoreKey` hash does,
  so a persistence breach yields **no redeemable tokens**. The subject *is* present in cleartext (it
  is PII, not a bearer credential), protected at the infrastructure layer as described above; a breach
  of the store discloses subject identifiers and grant metadata but grants no token-redemption or
  impersonation capability. This is the deliberate, Duende/OpenIddict-consistent trade for making
  by-subject revocation a reliable SQL predicate.

---

## Changelog

- 2026-07-15 — issue #376 (epic #352) — ADR created. Records the refresh-token store diverging from
  ADR 0013's opaque-KV model into a queryable persisted-grant store: new `IRefreshTokenGrantStore`
  (five methods, one CAS atomicity invariant), `RefreshTokenGrant` (cleartext queryable columns +
  one encrypted payload), `RefreshGrantStatus`; direct bulk family/subject revocation replacing the
  marker/metadata machinery; single `Unprotect` catch site; `AbsoluteFamilyLifetime` cap with
  mark-don't-delete and self-clean; relational-first backend guidance (Cosmos first-class with a
  partition-key note, Redis via a framework-owned adapter — not sanctioned DIY); a
  revocation-completeness conformance kit for exotic backends; renames
  `RefreshTokenConsumptionOutcome` → `RefreshTokenConsumptionResult`; seals `IRefreshTokenStore` via
  the ADR 0013 §1 internal-member pattern; deletes the refresh-token KV marker interface. Decides the
  issue's open question NO (`TryConsumeAsync` does not self-revoke). Depends on ADR 0013 (#375) for
  the shared `StoreKey`, sealing, `Guarded`, and accept-grace concepts it references.
- 2026-07-15 — security review — **COMPLETE, MIXED.** Items 2 (mark-don't-delete vs. absolute cap
  vs. accept-grace) and 3 (single `Unprotect` catch site) **signed off**. Item 1 (enlarged cleartext
  surface) **BLOCKED**: the operational/metadata columns and the random-GUID `FamilyId` cleared, but
  `SubjectHash` was a bare unkeyed SHA-256 over a guessable, low-entropy subject preimage and thus
  reversible to the raw subject by a read-only store observer. Unblock was said to require an
  HMAC-SHA256 keyed MAC (pepper).
- 2026-07-15 — security review (follow-up) — **ITEM 1 UNBLOCKED / SIGNED OFF; reversal of the BLOCK
  above.** The proposed HMAC-with-pepper fix was reconsidered and **rejected on operational grounds**:
  `RevokeBySubjectAsync` is a security control that must never fail to match, which is fundamentally
  incompatible with a rotatable secret — pepper rotation silently breaks subject-level revocation for
  every pre-rotation row, and a two-pepper scheme only defers the same failure at real complexity cost.
  Research into the two reference implementations this ADR invokes confirmed the correct posture:
  **neither Duende IdentityServer (`PersistedGrant.SubjectId`) nor OpenIddict (`OpenIddictToken.Subject`)
  hashes the subject at all** — both store it as a plain PII column and hash only the token *handle*
  (this ADR's `HandleHash`). The prior review's own premise (a bare hash over a guessable subject is
  trivially reversible for the in-scope read-only-DB attacker) shows the hash provided false confidence,
  not confidentiality — so honest cleartext is not materially weaker for that threat model. **Resolution:**
  replace `SubjectHash` (`StoreKey`, SHA-256-derived) with a plain cleartext `Subject` (`string`, NOT
  `StoreKey`), protected as PII by database-level access control, encryption at rest, and PII-handling
  policy — the Duende/OpenIddict posture, consistent with this ADR's own cleartext `FamilyId`. The
  residual deterministic cross-family correlation (intrinsic to any queryable subject column, never
  closed by the hash) is called out and accepted in Security Considerations. `RevokeBySubjectAsync` now
  takes a `string subject`. Item 1 signed off; all three items now cleared. Implementation may proceed
  once ADR 0013 (#375) is merged.
- 2026-07-18 — implementation (PR #383) — architect and security review of the implementation (not
  just the design) found and fixed two bugs: `StoreAsync`'s §5 clamp is now applied to the encrypted
  entry too (previously only the cleartext column was clamped, so `Consumed.Entry`/`FindAsync` could
  disagree with the enforced expiry); `InMemoryRefreshTokenGrantStore`'s family/subject revoke now
  locks against concurrent `InsertAsync` during its scan, closing a snapshot-enumeration race. Both
  reviews also independently confirmed a real gap neither this ADR's design sign-off nor ADR 0008
  addressed: `RevokeFamilyAsync`/`RevokeBySubjectAsync` do not gate a grant inserted *after* the
  revoke call returns into a family/subject with zero live rows at call time — an RFC 9700 §4.13
  completeness window, tracked separately as issue #386 and requiring its own security sign-off before
  any endpoint sequences consume→revoke. `IRefreshTokenGrantStore`'s XML docs were corrected to stop
  claiming completeness the implementation cannot structurally deliver for post-revoke inserts. Added
  `TokenEndpointOptions.ComputeFamilyAbsoluteExpiry` as a framework-owned, sentinel-safe helper for the
  birth-time `AbsoluteFamilyLifetime` → `FamilyAbsoluteExpiry` conversion, so a future caller can't
  re-derive the `TimeSpan.MaxValue` overflow trap independently. §8 amended with a shipped-status note:
  `DistributedCacheRefreshTokenGrantStore` fills the dev/test convenience slot only, not the
  production-grade Redis adapter this section anticipates.
- 2026-07-18 — issue #386 amendment — closes the post-revoke insert completeness gap
  (`RevokeFamilyAsync`/`RevokeBySubjectAsync` did not gate a grant inserted after the revoke call
  returned). Adds §11 and a sixth interface method `IsFamilyRevokedAsync` (read-only,
  strongly-consistent, fail-closed) consulted by `TryConsumeAsync` and `FindAsync` before honouring a
  grant's own `Active` status — **consume-time gating**, no write-path invariant. Rejects the
  insert-time born-`Revoked` gate (write-path protocol decision + isolation-sensitive second atomic
  invariant), insert-then-verify-then-revoke (two-phase write with an unbounded crash-durability gap),
  and an insert-time defence-in-depth check (false-confidence, re-imports the coupling for no
  coverage). §3 updated five→six methods; §9 conformance kit gains a strictly-after-revoke insert case
  plus an `IsFamilyRevokedAsync` fail-closed case; records a bounded, attacker-timed, one-rotation
  self-healing residual race as accepted. Security sign-off granted 2026-07-18 (banner amendment),
  scoped to this fix only. Implementation deletes the now-obsolete "Known gap (issue #386)" remarks on
  `RevokeFamilyAsync`/`RevokeBySubjectAsync` in `IRefreshTokenGrantStore.cs`.
- 2026-07-18 — issue #388 amendment — closes the zero-row-family revocation gap §11's "familyId always
  comes from an existing row" assumption left open (an auth-code replayed before its first refresh
  token is stored lets `RevokeFamilyAsync` run against a family with no rows and leave no trace for the
  §11 gate). Adds §12: `RevokeFamilyAsync` now unconditionally inserts one durable `Revoked`
  revocation-sentinel row, keyed deterministically on `familyId` (`H("revocation-sentinel:" +
  familyId)`) so repeated revokes stay idempotent with no row growth, with reserved non-colliding
  `Subject`/`ClientId` constants, an empty `ProtectedPayload`, and `FamilyAbsoluteExpiry` computed the
  same way a real family's is (`ComputeFamilyAbsoluteExpiry`) — **not** bounded by the shorter
  auth-code lifetime. No new interface method and no public `InsertAsync` contract change: insert-if-
  absent for the one reserved sentinel key is a coordinator-internal catch-the-self-collision helper.
  Rejects a separate `revoked_families` marker table (re-adds removed marker machinery), endpoint-side
  sequencing (cannot observe an in-flight `StoreAsync`, and would weaken the RFC 9700 §4.13 defence),
  an auth-code-lifetime-bounded sentinel expiry (fails open once swept before a successor's longer
  lifetime ends), and a random per-call sentinel key (breaks idempotency, unbounded growth). §9
  conformance kit gains a zero-row-family case. Implementation lives **entirely in the framework
  coordinator** (`RefreshTokenStore.RevokeFamilyAsync`), composing the existing
  `_grantStore.InsertAsync` (sentinel) + `_grantStore.RevokeFamilyAsync` (bulk mark) primitives — no
  backend file (`InMemoryRefreshTokenGrantStore`, `DistributedCacheRefreshTokenGrantStore`) and no
  interface is touched, since sentinel construction is protocol and belongs in the coordinator per
  ADR 0014's coordinator-owns-protocol split. **Security sign-off pending review
  of the shipped implementation** (design reviewed and approved pre-implementation; banner entry marked
  PENDING, not granted).
