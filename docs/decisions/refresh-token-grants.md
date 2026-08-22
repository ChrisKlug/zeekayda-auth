# Refresh-token grants

Refresh-token-specific rules. The coordinator/backing-store split, `StoreKey`, fail-closed I/O,
registration policy and the shared options live in `token-stores.md` and apply here unchanged.

## Decisions in force

**Refresh tokens are a queryable persisted-grant store, not an opaque key-value blob.** A grant is
one structured row: non-secret queryable columns on the outside, one Data-Protection payload the
backend stores verbatim and never interprets. Revocation by family (RFC 9700 §4.13) and by subject
are predicates over live rows — `UPDATE … WHERE family_id = @f` — which no opaque blob can express.
This is the model Duende IdentityServer and OpenIddict use. Going queryable *removed* machinery: the
per-family metadata record, the enumeration-free revocation marker and the problem of sizing its TTL
from a bare `familyId`, the four-namespace key layout, the second write per store, and one of the two
decryption catch sites all disappeared with the `WHERE` they were working around.

**The queryable columns are honest cleartext, including the subject.** None of them is a bearer
credential — the handle only ever reaches the store as a hash — so a persistence breach discloses
grant metadata and subject identifiers, never anything redeemable. The subject is PII and is
protected at the infrastructure layer: least-privilege database roles, encryption at rest, and
ordinary PII policy over the whole table. Accepted residual: a deterministic, queryable subject
column lets a read-only observer see that many families share one subject and correlate a user's
grants over months. That is intrinsic to having a queryable subject at all — the price of by-subject
revocation — and it is wider than the per-family correlation the code store carries. Signed off.

**No security decision rides on a successful decrypt.** Reuse, revocation, client mismatch and expiry
are all decided from cleartext columns before anything is decrypted. The single decryption is on the
consumed happy path, and its failure resolves `NotFound` — fail-closed, because the token has already
been marked consumed, so no successor is issued and no reuse is enabled. One catch site, one
semantic; the asymmetry the code store needs does not exist here. Signed off.

**Mark, don't delete.** Consume and revoke mutate the status column; nothing on the hot path deletes.
A still-live token in a revoked family must read as revoked and a replayed token must read as already
consumed — deleting turns both into `NotFound`, the wrong signal, and throws away the tombstone that
reuse detection and family revocation depend on.

**One absolute ceiling per family, clamped into the token and into its payload.** The family's
absolute expiry is baked at the birth of its first token and propagated verbatim through every
rotation; each token's own expiry is `min(now + RefreshTokenLifetime, FamilyAbsoluteExpiry)`, applied
to the encrypted entry as well as the cleartext column so a caller reading the decrypted entry can
never see a longer expiry than the one actually enforced. `RefreshTokenLifetime` *is* the idle
window; there is no separate idle option. `AbsoluteFamilyLifetime` defaults to 90 days, and the
`TimeSpan.MaxValue` sentinel disables the cap and warns at startup — unbounded row growth is a
resource concern and an explicit opt-in, not a fail-open. Any cleanup must retain a row until it is
past the family's absolute expiry by more than `ClockSkewTolerance`, so accept-grace can never need a
tombstone that cleanup has already removed.

**A revoked family kills a grant regardless of that grant's own status.** Both consumption and lookup
consult `IsFamilyRevokedAsync` before honouring an active row, because a bulk revoke marks only the
rows its predicate can see and a successor can be inserted afterwards. That read MUST be strongly
consistent against the primary and MUST throw on fault: a stale replica or a fault masked as `false`
reads as "not revoked" and fails open, the same failure class as masking a read fault as absence.
Gating at consume time rather than write time is what makes it crash-safe — every redeem re-derives
family state from what is durably committed at that instant, so there is no multi-step write to
interrupt and insert/revoke ordering stops mattering. Signed off. Accepted residual: a consume that
passes the gate microseconds before a concurrent revoke commits mints one successor, which then dies
at its own next consume — inherent to any detect-and-revoke design, and it self-heals in one
rotation.

**Revoking a family always writes a revocation sentinel.** A family can hold zero rows at the moment
it is revoked — an authorization code replayed before its first refresh token has committed — and a
bulk update then matches nothing and leaves no trace for the gate to find. So the coordinator
unconditionally inserts one durable revoked row for the family, keyed deterministically on the family
id, with reserved non-colliding subject and client values and an empty payload, so it can never be
redeemed. The key is deterministic so repeated revokes converge on one row instead of growing
unboundedly. Its expiry is computed the same way a real family's is and **must not** be bounded by
the much shorter authorization-code lifetime, or the sentinel is cleaned up while a genuine successor
is still live and the family silently un-revokes. The insert is insert-if-absent for that one
reserved key: because every native fault is flattened into one exception type, exception shape alone
cannot distinguish a benign self-collision from a transport failure, so on any failure the
coordinator re-reads the sentinel and propagates the original exception unless the row is confirmed
durable. All of this lives in the coordinator — no backend and no interface member changed.

**Consumption does not self-revoke on reuse detection.** It reports the reuse and its family id, and
the caller revokes. Queryability makes self-revoke technically free now, and it is still refused for
two reasons: reuse is also detected by the authorization-code coordinator, which holds no reference
to this one, so self-revoking here would automate one trigger and leave the other manual and
surprising; and "try to consume" quietly revoking an entire token family is exactly the hidden
behaviour this framework refuses to ship. Sequencing consume/redeem, inspect, revoke consistently
across both triggers belongs to the endpoints, each deciding its own shape when it is built.

**The grant store gets no bulk read and no cleanup method.** The coordinator never needs to read a
whole family or subject, only to revoke them, so a bulk read would be an enumeration and leak surface
for nothing; the capability is expressed purely as the revoke predicate. Expired-row cleanup is a
maintenance concern — native per-item TTL where a backend has one — not coordinator protocol, and can
be added compatibly if it is ever needed.

**By-subject revocation is a capability, not a shipped feature.** The predicate exists on the grant
store; no coordinator method and no endpoint calls it. Logout-all needs a session model, its own
authentication and audit story, and RP-initiated-logout semantics. Do not read the column or the
method as a delivered feature.

**Relational-first.** SQL gives the compare-and-set and both revocation predicates natively, and its
only "remember to" is two indexes — whose absence is a pure performance regression, never a wrong
answer. Cosmos is correctness-safe with a partition-key choice that affects only cost. A backend
without `WHERE` must hand-maintain family and subject index sets as a non-transactional dual write
that drifts on a partial-write crash, leaving a live grant revocation will never see — silent, and
invisible to single-token happy-path tests. The shipped distributed-cache grant store does exactly
that and is development and test only; the framework-owned adapter that would own index maintenance
correctly, once, is unbuilt.

## Tried, didn't work

- **A hashed subject column.** Built as a bare SHA-256, blocked in security review, and the review's
  own HMAC-with-pepper remedy was then rejected in favour of honest cleartext — reversing the block.
  Over a guessable, enumerable preimage (sequential ids, email addresses) a read-only observer
  reverses the hash trivially, so it bought false confidence rather than confidentiality; and
  by-subject revocation is a control that must never fail to match, which is incompatible with a
  rotatable secret — rotating the pepper silently breaks revocation for every pre-rotation row, and a
  two-pepper scheme only defers the same failure at real cost. Both reference implementations store
  the subject as a plain column and hash only the handle. Anyone proposing to hash or pepper the
  subject should stop here.
- **Redis as a first-class, hand-rolled target.** The earlier key-value model sanctioned any KV store,
  Redis included. Reversed with the queryable model: every Redis trap — missing index, non-atomic
  dual write, cross-slot cluster atomicity, partial-write drift — compiles, passes a happy-path test,
  and silently breaks family revocation. Keeping the queryable interface and shipping one
  framework-owned adapter is the fix; documenting the index requirement is not.
- **Deciding revocation on the write path.** Two variants, one failure class: an insert that chooses
  active-versus-revoked via a cross-row conditional write puts a protocol decision on the interface
  third parties implement and adds a second atomic invariant that only serialises under SERIALIZABLE
  or an explicit family lock; a coordinator that inserts, then verifies, then re-revokes is a
  two-phase write with no compensating action, so a crash between the phases leaves a permanently
  active grant in a revoked family. Consume-time gating needs no write-path invariant at all, and a
  best-effort write-path check *alongside* it only implies a robustness it cannot provide.
