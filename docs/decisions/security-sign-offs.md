# Security sign-offs

Dated, commit-scoped records of security approvals for trust-boundary decisions in ZeeKayDa.Auth.

**This file is exempt from the decision-register format and from the 150-line CI cap** (the check
skips it by name — see `.github/workflows/ci.yml` and `docs/decisions/README.md`). Every other file
in this directory answers "what is true now?" and deliberately drops history. A security sign-off is
not a statement about now: it is the record that *a specific change*, *against a specific commit or
PR*, was reviewed, what the review did and did **not** cover, what conditions were attached, and
which residual risks were explicitly accepted with no mitigation. Losing any of that turns a
reasoned acceptance into an undocumented gap.

**Rules for this file.** Append; do not rewrite. Corrections are appended as new entries, not edits
to old ones — a reversal is itself the audit-relevant fact and is recorded as a reversal. Scope
limits and explicit negatives ("this sign-off did not cover X") are as load-bearing as the approval
and are never trimmed. Where a decision has since changed, the register file for that topic is
authoritative for *current* behaviour; this file remains authoritative for *what was approved when*.

*Archaeology note:* these records were extracted from the numbered ADRs that preceded the decision
register (ADRs 0011, 0013, 0014 and 0016 in particular). Those documents are being retired and
deleted as each topic is migrated — nothing here depends on an ADR number resolving, and this file
is the surviving record once they are gone.

---

## 1. Signing keys, the JWKS trust boundary, and the provider contract

### 1.1 `RetirementWindow` derivation and JWKS exposure — ✅ signed off (round 1, original design)

**Approved by:** the security agent, as a token-validation trust-boundary decision, before the
original signing-key ADR merged.
**Approved against:** the original signing-key design (issue #187).

**What was approved.** The derivation

```
RetirementWindow = max(access-token lifetime, ID-token lifetime, 1-hour floor) + clock-skew allowance
```

measured from the moment a *successor* key becomes active (not from the retired key's creation),
being **derived and never operator-configurable**; and the JWKS exposure behaviour — that
`IJwksDocumentProvider` publishes exactly the active key plus every key still inside its retirement
window, since what appears in the JWKS is what relying parties will trust.

This sign-off still governs today's derivation, which is unchanged.

**Explicit scope limit — what this sign-off did NOT cover.** It was scoped to the `RetirementWindow`
derivation and JWKS exposure *specifically*. It did **not** separately re-approve:

- the dev-key environment gate,
- minimum key strength,
- the PEM hardening rules (`0700`/`0600` atomic create-time permissions, symlink and
  directory-ownership fail-closed checks).

Those were not touched by anything reviewed in round 2 either, and remain governed by ordinary code
review — not by a security sign-off.

**Recorded rationale that is part of the approval.** Refresh-token lifetime is deliberately excluded
from the `max(...)`: refresh tokens are validated by the authorization server against the token
store, never by a relying party against the JWKS, so including their unbounded sliding lifetime
would pin every retired key in the JWKS for no validation benefit. The 1-hour floor is a temporary
bridge — ID-token and access-token lifetimes are not yet configurable, so without a floor the
`max(...)` resolves over zero terms and produces a near-zero window that invalidates tokens in
flight.

### 1.2 First production provider — Azure Key Vault remote signing — ✅ signed off, two rounds

**Approved by:** joint security + architect review. **Two rounds, both APPROVE, no blocking
findings.**
**Approved against:** PR #298. Round 1 reviewed that PR's design and diff directly. **Round 2 was
against commit `ea5c9b1`.**

**What round 2 closed.** Commit `ea5c9b1` closed a closed-generic `ISanitizingLogger<T>` shadowing
gap that round 1 had flagged and accepted as a residual. The fix is the startup control now called
`SanitizingLoggerRegistrationGate`: it runs before every other startup check and rejects both an
unexpected open-generic implementation and any closed-generic override, so a host cannot silently
disable log redaction on the signing path. (The gap existed because `ISanitizingLogger<T>` is
deliberately `public` so out-of-package providers can inject it; making it nameable made host
shadowing reachable.)

**Residual risk explicitly accepted, with no mitigation.** A Key Vault **list-key-versions
read-consistency** question was raised during that review. It was investigated against Microsoft's
documented reliability model and the residual was **accepted as-is, with no mitigation**. Basis for
acceptance: the only affected case is a brand-new key during a rare Microsoft-initiated regional
failover; that case is self-healing and is never a security regression.

*Provenance caveat:* `ea5c9b1` does not resolve as an object in the current repository (the branch
commit did not survive the squash-merge). It is preserved verbatim as the reviewer recorded it.

### 1.3 Provider-contract reshape — `KeySetOptions` / `KeySourceOptions` — ✅ approve **with conditions**

**Approved by:** the security agent, returning *approve-with-conditions*; **@ChrisKlug adjudicated**
the conditions.
**Approved against:** PR #419 (the two-tier `KeySetOptions` / `KeySourceOptions` reshape, originally
ADR 0015).

Both must-fix conditions and the should-fix notes were folded into the shipped decision text rather
than left outstanding.

**Must-fix condition 1 — `PublicationLead` durability.** `PublicationLead` MUST be durable and
`ActivateAt`-derived (`PublishAt = ActivateAt − PublicationLead`). It must **never** be derived from
observed or first-seen time. This preserves the ban on in-memory, restart-inconsistent and
replica-inconsistent observed-time bookkeeping. *Status: resolved in the shipped design.*

**Must-fix condition 2 — kill-by-omission must be a disambiguated signal, not an overloaded one.**
There is no `Enabled` flag; a key vanishing from `ListKeysAsync` is the kill switch. The three states
must be distinguishable:

1. **post-window vanish** — normal end of life; silent, no log beyond routine;
2. **within-window vanish** — the key is still dropped from the JWKS on the next refresh (the kill
   switch still fires), but the base **MUST** emit a `Warning`. That `Warning` **MUST NOT** be
   downgraded to info or to observability. It is the sole remaining detector for accidental early key
   omission, replacing the capability the removed `Enabled` model provided;
3. **failed or partial read — MUST throw.** `ListKeysAsync`'s completeness contract (MUST throw,
   never return a short list) is what stops a partial read being misread as a revocation.

*Status: resolved in the shipped design.*

**Residual risk explicitly accepted as-is, no mitigation required.** The relaxation of retired
private-key destruction from "immediately on retirement" to "**bounded by request cadence, reclaimed
on the next recompute or at shutdown**". Basis for acceptance: the base class requests private
material only for the *active* key, so keeping non-active private material out of process memory is
a **provider obligation** for bundled formats (PFX, certificate store), not a structural guarantee
the framework offers.

**Should-fix notes, folded in (not left outstanding):**

- duplicate-`kid` rejection restated as running on **derived thumbprints at `ListKeysAsync` time**;
- `ISigner.Dispose` must-not-dispose-a-shared-client raised from guidance to a **contract MUST**;
- an optional `KeySetOptions` scavenge timer noted as a way to bound the idle-app worst case for
  superseded-signer disposal — **a noted possibility, not a requirement**.

**Also reviewed and found sound — no fail-closed gap.** During the `PublicationLead` window the prior
active key stays active until the successor's `ActivateAt`; a newly published key never removes the
incumbent, so `SelectActiveKey` returns `null` only when every configured key has expired.

**Operational gap recorded by the same review (real, if narrow; not blocking).** A `KeySetOptions`
deployment whose active key expires with **no configured successor** drifts to that same `null` and
**fails closed at request time**. The startup too-soon-activation warning covers *activation timing*,
not *eventual expiry*, so nothing warns an operator ahead of it. Operators should be aware of it.

### 1.4 Windows Certificate Store provider — pairing check originated as a review finding

**Source:** security review of PR #436 (Windows Certificate Store signing provider).

That review produced the finding that led to the provider's hand-rolled
`VerifySigningKeyMatchesListing` — a check that the signer actually pairs with the published public
key. That provider-local check has since been **superseded** by the generic per-handoff signing
self-test (see 1.5), which proves the same invariant on every handoff for every provider.

### 1.5 Explicit negative — the per-handoff signing self-test is **NOT covered by any sign-off** (review tracked by #487)

The per-handoff signing self-test (issue #437) — the sign-and-verify-against-the-listed-public-key
step inside `EnsureActiveSignerAsync`, its `ISigningStartupSelfTest` seam, and the
`SigningStartupSelfTestVerifier` that forces the first handoff eagerly at startup — was added
**after** both reviews in 1.1–1.3 and **is not covered by either sign-off**. It generalises the
pairing check that originated as the PR #436 finding above, but it has not itself been signed off.

Design properties recorded at the time it was built, for whoever reviews it: the self-test is
**unconditional, with no HSM opt-out** (secure-by-default), it signs a fixed non-JWS-shaped constant
(`"zeekayda-auth signing self-test"` — contains a space and no `.`, so it can never be mistaken for
or lifted into a valid JWS), it runs before the signer is installed as active or handed out, and a
self-test that cannot complete aborts the handoff exactly as a definitive mismatch does.

### 1.6 `InternalsVisibleTo` for POSIX interop — a narrow, reviewed exception

`ZeeKayDa.Auth.FileSystem` is granted `InternalsVisibleTo` from core so it can reuse core's
`internal` POSIX `stat`/`lstat` P/Invoke for symlink-ownership validation rather than forking it.
This is one of two narrow, **reviewed** exceptions for a first-party assembly shipping in lockstep
with core (the other is `ZeeKayDa.Auth.Windows` reusing `ProcessIdentityHelper`).

The security-relevant justification, which is why the exception was granted rather than the code
duplicated: this interop already needed a **security-review fix for a symlink-following bug
(`stat()` vs `lstat()`)**, and a forked copy would risk a second, independently-drifting copy of that
same security-critical, platform-ABI-dependent code. It is **not** a pattern other providers, first-
or third-party, should reach for; a provider that can meet its needs through core's public surface
must do so.

---

## 2. Authorization-code store

### 2.1 Plaintext `FamilyId` in the redemption tombstone — ✅ signed off 2026-07-15

**Approved by:** security review, 2026-07-15.
**Approved against:** the authorization-code store protocol/persistence split (issue #375).
**Verdict:** ✅ **granted — for the authorization-code store only.**

**What was approved.** Changing the redemption tombstone from a single all-ciphertext blob to a small
envelope, `{ FamilyId: plaintext string, ProtectedSecret: DP-ciphertext }`, so that
`AlreadyRedeemed{FamilyId}` (RFC 9700 §2.1.1 replay handling) **survives a Data Protection key
rotation**.

**Basis for approval, recorded as part of the sign-off.** `FamilyId` is a random identifier used only
as a non-secret correlation / revocation-lookup value. Revocation is driven only by the plaintext
`FamilyId` value itself, never by the raw code handle; `RevokeFamilyAsync` is framework-internal and
unreachable by a read-only store observer. A leaked `FamilyId` therefore **grants no capability,
forges no token, and enables no redemption** — it discloses correlation, not a bearer credential.

Two facts **specific to the code store** were load-bearing in the approval:

1. the tombstone's backend TTL is the code's own seconds-to-minutes lifetime, so the cleartext exists
   only briefly; and
2. **each authorization code maps to a distinct, freshly-minted family**, so a `FamilyId` appears in
   at most one code tombstone — there is no rotation chain to correlate.

The rotation-survival benefit was judged a strict security improvement outweighing the narrow,
short-lived correlation surface.

**Explicit scope limit — what this sign-off did NOT cover.**

- **Not the refresh-token store.** Chains exist only in the refresh-token store, which was required
  to obtain its own, separate sign-off (see §3). This approval is **not** inherited by it.
- **Not a multi-code family chain.** The approval is *predicated* on one-code-one-family. Reusing a
  `familyId` across codes extends a "single code, single family" correlation surface into a
  **multi-code chain the security sign-off did not evaluate**.

**Condition attached (enforcement lives outside the store).** Nothing inside the store enforces
one-code-one-family — `TryRedeemAsync` accepts whatever `familyId` string the caller supplies. The
token-issuing endpoint **MUST** mint a fresh, never-reused `familyId` per authorization code. At the
time of writing that endpoint was **not yet built**, so this is an obligation on a component that did
not exist when the sign-off was granted.

**Condition strengthened after the sign-off text was written.** The banner's original wording said
"random GUID". The operative requirement is stronger and supersedes that phrasing: `familyId` **MUST
be minted via a CSPRNG, never `Guid.NewGuid()`** — concretely from `StoreKeyGenerator.Generate()` (or
an equivalent CSPRNG producing at least 128 bits of entropy), because a GUID carries only ~122 bits
of entropy in its random variant and is not a documented CSPRNG source. `StoreKeyGenerator.Generate()`
ships in `ZeeKayDa.Auth.Stores` as a 256-bit `RandomNumberGenerator`-backed generator whose remarks
prohibit `System.Random` / `Guid.NewGuid()` / `Random.Shared`.

### 2.2 Tombstone retention = the code's own lifetime — reviewed and accepted, **Low**

**Status:** confirmed-shipped, **security-reviewed-and-accepted** behaviour. Not a gap to close.

`AuthorizationCodeStore` computes the tombstone's expiry as `entry.ExpiresAt + ClockSkewTolerance` —
the authorization code's own short (default 60s) lifetime plus clock-skew grace — **not**
`RefreshTokenLifetime`.

**Residual risk explicitly accepted.** A code replayed *after* the tombstone has expired resolves
`NotFound` rather than `AlreadyRedeemed{FamilyId}`, so **no family revocation fires** for a
late-surfacing interception/replay of an already-expired code.

**Severity accepted at: Low.** Basis: the code itself is by then unredeemable regardless of which
outcome is returned, so the missed revocation costs nothing an attacker could exploit — the code that
would have driven the revocation can no longer mint a token.

### 2.3 Residual risks accepted alongside the above

- **Read-only-observer correlation.** A read-only store observer can correlate a redeemed code's
  tombstone to its refresh-token family via the cleartext `FamilyId`. Accepted per §2.1 (non-bearer,
  short-lived, one family per code).
- **Atomicity is unprovable.** The CLR cannot prove a given `TryInsertAsync` implementation is
  actually atomic. That ceiling is **irreducible** and is *mitigated only* by mapping guidance (Redis
  `SET NX`, SQL unique-constraint `INSERT`, Cosmos conditional create) and the
  `ZeeKayDa.Auth.TestKit` conformance case — **not eliminated**.
- **The distributed-cache default's check-then-set race is a measurable bypass, not a benign
  curiosity.** An attacker racing a legitimate rotation can extend a revoked family's usable window
  by **one rotation cycle**. This is why the shipped `InMemory*`/`DistributedCache*` defaults are
  positioned as **dev/test-only**, explicitly *not* as "acceptable for single-instance production".
  Multi-instance production requires a custom atomic backing store.

---

## 3. Refresh-token grant store

### 3.0 Sign-off was required *before* implementation, and was not inheritable

The refresh-token store's sign-off requirement was raised as ⚠️ **REQUIRED, NOT YET GRANTED** on
2026-07-15, with implementation (issue #376) blocked until it was granted. It was explicitly **not**
inherited from the authorization-code store's sign-off (§2.1): the refresh-token store has a
materially larger cleartext surface and much longer-lived records, so it needed its own assessment.
Three items required explicit sign-off. All three were ultimately cleared — one of them only after a
**BLOCK that was subsequently reversed**.

### 3.1 Item 1 — enlarged cleartext queryable columns, including `Subject`

#### 3.1a First review, 2026-07-15 — ❌ **BLOCKED** (this verdict was later reversed)

**Partial clearance.** The operational/metadata columns cleared: `ClientId`,
`FamilyAbsoluteExpiry`, `ExpiresAt`, `Status`, and the random `FamilyId` — none is a bearer
credential, they disclose only operational/correlation metadata already implied by a grant's
existence, and `FamilyId`'s reasoning transfers directly from §2.1 (random 128-bit, unguessable, no
capability if leaked). `HandleHash` cleared as a bare SHA-256 **because its preimage is a 256-bit
random handle**, so it resists reversal.

**The block.** The original design stored the subject as `StoreKey(H(entry.Sub))` — a **bare unkeyed
SHA-256**. Over a guessable, low-entropy, enumerable preimage (sequential ids, email addresses) a
read-only store observer reverses that hash by rainbow table trivially. "Hashed" therefore bought no
confidentiality against the very attacker in scope; it only created **false confidence that a control
existed**. The review's stated unblock requirement was an **HMAC-SHA256 keyed MAC (pepper)**.

#### 3.1b Follow-up review, same day 2026-07-15 — ✅ **SIGN-OFF; the BLOCK is reversed**

**This is a reversal, recorded as such.** The HMAC-with-pepper fix that the first review demanded was
reconsidered and **rejected on operational grounds**: `RevokeBySubjectAsync` is a security control
that **must never fail to match**, which is fundamentally incompatible with a keyed secret that gets
rotated. Rotating the pepper silently breaks subject-level revocation for every pre-rotation row, and
a two-pepper scheme only defers the same failure at real complexity cost.

**What was approved instead.** The subject is stored as an **honestly-named cleartext `Subject`
string**, not a hash. `RevokeBySubjectAsync` takes a `string subject`.

**Basis for the reversal.**

- The prior review's *own* premise — a bare hash over a guessable subject is trivially reversible for
  the in-scope read-only-DB attacker — shows the hash provided false confidence, not confidentiality.
  For that threat model **cleartext is not materially worse than the blocked hash**: both expose the
  raw subject; cleartext simply removes a reversal step that was already cheap, and stops overstating
  the protection.
- Both reference implementations the store is modelled on confirm the posture: **neither Duende
  IdentityServer (`PersistedGrant.SubjectId`) nor OpenIddict (`OpenIddictToken.Subject`) hashes the
  subject at all** — both store it as a plain PII/foreign-key column and hash only the token *handle*.

**Compensating controls the approval depends on (infrastructure layer, not application layer).** The
subject is protected as PII by **database-level access control (least-privilege roles), encryption at
rest (disk/backend level), and standard PII-handling policy over the whole grant table**. The
sign-off explicitly declines to substitute an application-level hash for these.

**Residual risk explicitly accepted, no mitigation.** Because `Subject` is deterministic and
queryable, a read-only observer with DB read access can see that N families share one subject and
**correlate a user's grants across families over months** — a wider correlation scope than
`FamilyId`'s per-chain scope. This is **intrinsic to having a queryable subject column at all** (the
price of `RevokeBySubjectAsync`), was never closed by the previously-proposed hash, and is not
widened by cleartext. **Accepted as the cost of the capability.**

**Recorded as a deliberate change to the store's earlier data-protection posture.** This moves the
subject from an encrypted-payload-only treatment to an **additional** cleartext queryable column (the
encrypted copy still lives inside `ProtectedPayload`). That at-rest exposure is the deliberate,
necessary cost of making by-subject revocation a SQL predicate.

**Scope of what a breach yields.** A read-only observer of this column set learns only which client
and subject a grant binds, its lifecycle state, and its expiries — **no bearer credential and no
token-redeemable material**. The raw handle never reaches the store.

### 3.2 Item 2 — mark-don't-delete vs. absolute cap vs. accept-grace — ✅ SIGN-OFF (2026-07-15)

**What was verified.** The arithmetic composes safely:

- A grant is honoured only while `Status == Active` **and** `now < ExpiresAt + ClockSkewTolerance`.
- The clamp guarantees `ExpiresAt <= FamilyAbsoluteExpiry`, so the latest honour instant is
  `FamilyAbsoluteExpiry + skew` — the accept-grace band applied consistently, **not** an over-run of
  policy.
- The sweep predicate `family_absolute_expiry < now - skew` deletes a row only after
  `now > FamilyAbsoluteExpiry + skew`, i.e. strictly after every token in that family has passed its
  own accept-grace window — so **a tombstone is never physically removed while still needed for reuse
  detection**.
- `FamilyAbsoluteExpiry` is shared verbatim across the whole family, so the family is swept
  atomically; no split-sweep leaves a live sibling without its family's tombstones.
- Status-before-expiry ordering in `TryConsumeAsync` means the reuse/revoked signal is only ever lost
  to `NotFound` after the token is independently expired and unredeemable anyway.

**Residual accepted.** The `DateTimeOffset.MaxValue` sentinel disables both the cap and the sweep,
giving unbounded row growth. Classified as a **resource concern, not a fail-open one**, and it is a
warned, explicit opt-in (the framework warns at startup when it is configured).

**Non-blocking implementation note attached to the sign-off.** Guard `now + RefreshTokenLifetime` and
`ExpiresAt + ClockSkewTolerance` against `DateTimeOffset` overflow near the sentinel.

### 3.3 Item 3 — single `Unprotect` catch site — ✅ SIGN-OFF (2026-07-15)

**What was verified**, against the consume flow: `NotFound` (null), `Revoked`, `AlreadyConsumed`
(reuse), accept-grace expiry, and `ClientMismatch` are **all decided from cleartext columns before
the CAS and before any `Unprotect`**; the CAS pivots on the `Status` column; the lost-race re-read
branch reads cleartext only. The sole `Unprotect` runs *after* the CAS has already marked the row
`Consumed`, on the happy path, and its failure degrades to `NotFound` — **fail-closed** (the token is
already dead, no successor issued, no reuse enabled). `RevokeFamilyAsync` / `RevokeBySubjectAsync`
are cleartext-predicate only.

**Conclusion:** no security decision anywhere in the coordinator rides on a successful decrypt, so
collapsing from the authorization-code store's two catch sites to one **reintroduces no fail-open
path**. Confirmed sound.

### 3.4 Implementation review of PR #383 — two bugs found and fixed, one new gap opened

**Reviewed by:** architect **and** security, reviewing the *implementation*, not just the design.
**Reviewed against:** PR #383. **Date:** 2026-07-18.

**Bugs found and fixed in that PR:**

1. `StoreAsync`'s absolute-lifetime clamp is now applied to the **encrypted entry too** — previously
   only the cleartext column was clamped, so `Consumed.Entry` / `FindAsync` could disagree with the
   enforced expiry.
2. `InMemoryRefreshTokenGrantStore`'s family/subject revoke now **locks against concurrent
   `InsertAsync` during its scan**, closing a snapshot-enumeration race.

**A real gap both reviews independently confirmed, which no prior sign-off had addressed.**
`RevokeFamilyAsync` / `RevokeBySubjectAsync` did **not** gate a grant inserted *after* the revoke call
returned into a family/subject that had zero live rows at call time — an RFC 9700 §4.13 completeness
window. It was tracked as issue #386 and was recorded as **requiring its own security sign-off before
any endpoint sequences consume→revoke** (see §3.5, where that sign-off was granted).

`IRefreshTokenGrantStore`'s XML docs were corrected in the same PR to stop claiming a completeness
the implementation could not structurally deliver for post-revoke inserts.

### 3.5 Issue #386 amendment — consume-time family-revoked gate — ✅ SIGN-OFF, **conditional** (2026-07-18)

**Scope: *only* the consume-time family-revoked gate added by this amendment.** The three items in
§3.1–3.3 are unchanged and **not re-opened**.

**What was approved.** One read-only method, `IsFamilyRevokedAsync`, consulted by `TryConsumeAsync`
and `FindAsync` before honouring a grant's own `Active` status — so a successor inserted after a
`RevokeFamilyAsync` is caught at **its** redeem, not at write time. **No new write-path invariant, no
two-phase write.**

**Conditions the sign-off is explicitly conditional on** (the contract MUST hold):

- `IsFamilyRevokedAsync` **MUST be a strongly-consistent / primary read.** A stale read-replica that
  misses a just-committed revoke **fails open**.
- It **MUST throw on transport/backend fault** and **MUST NOT catch-and-return `false`.** A
  `false`-masked fault reads as "not revoked" and defeats the gate — the same failure class as
  `FindByHandleAsync`'s fail-closed contract.
- The conformance kit gains two cases: a grant inserted **strictly after** `RevokeFamilyAsync`
  returns MUST be reported revoked by a subsequent consume (distinct from the existing
  concurrent-overlap case), plus a fail-closed fault-propagation case for `IsFamilyRevokedAsync`.

**Residual risk explicitly accepted (bounded, attacker-timed).** A consume's `IsFamilyRevokedAsync`
can pass microseconds before a concurrent `RevokeFamilyAsync` commits, letting that one consume mint
a successor — which then dies at *its own* next consume, one rotation later. This live-request window
is inherent to every detect-and-revoke design (RFC 9700 §4.13 always has one), needs **active racing
rather than a passive failure**, and self-heals in one rotation. **Accepted, not a gap.**

**Explicit negative.** The rejected insert-time defence-in-depth check is **explicitly not added** —
it was assessed as false confidence that re-imports the coupling for no coverage.

### 3.6 Issue #388 amendment — zero-row-family revocation sentinel — ⏳ **PENDING; NOT A SIGN-OFF** — tracked by #485

**Status as recorded: ⏳ PENDING SECURITY REVIEW OF THE IMPLEMENTATION.** The design was discussed and
approved pre-implementation (architect proposal + security critique). **Security has not reviewed the
shipped code. This entry is explicitly not a sign-off.** See §5 for the open action item.

**Scope, if and when reviewed:** *only* the revocation-sentinel fix. §3.5 and the three original items
are unchanged and not re-opened.

**The gap it closes.** §3.5's gate rests on "`familyId` is only ever obtained from an existing row",
so a revoke always leaves at least one durable tombstone. An authorization code replayed **before its
first refresh token is stored** breaks that: the winner's auth-code CAS succeeds and it begins minting
`RT1`, while the loser detects the replay and calls `RevokeFamilyAsync(familyId)` — but at that
instant the family has **zero rows**, the `UPDATE ... WHERE family_id = @f` matches nothing, and no
trace is left. When `RT1`'s insert lands `Active`, the §3.5 gate finds no `Revoked` sibling and `RT1`
is a live token in a family that was explicitly revoked — the RFC 9700 §4.13 hole reopened one layer
down.

**The shipped fix.** `RevokeFamilyAsync` unconditionally inserts one durable `Revoked`
revocation-sentinel row, keyed deterministically on `familyId` (`H("revocation-sentinel:" +
familyId)`), with reserved non-colliding `Subject`/`ClientId` constants, an **empty**
`ProtectedPayload`, and `FamilyAbsoluteExpiry` computed the same way a real family's is
(`ComputeFamilyAbsoluteExpiry`) — **not** bounded by the shorter auth-code lifetime. No new interface
method; no public `InsertAsync` contract change. It lives entirely in the framework coordinator
(`RefreshTokenStore.RevokeFamilyAsync`); no backend and no interface is touched.

**Two design errors caught in critique/review before this write-up — preserved because they are the
failure modes a reviewer should re-test for:**

1. An earlier draft bounded the sentinel's expiry by the **auth-code lifetime**. That **failed open**:
   the sentinel would be swept before a genuinely-inserted successor's own much longer lifetime ended,
   silently reopening the gap.
2. An earlier draft **swallowed the sentinel-insert exception unconditionally**, which would have
   silently masked a genuine transport fault as success. The shipped code instead re-reads the
   sentinel's key via `FindByHandleAsync` to confirm the row is durably present and `Revoked` before
   treating an insert failure as a benign self-collision; if the confirming read shows the sentinel
   genuinely absent, **or the read itself throws**, the original exception propagates.
   `RevokeFamilyAsync` must never return successfully while the sentinel is not confirmed durable.
   This matters because `Guarded(...)` flattens every native fault into the same
   `ZeeKayDaStoreException`, so a real fault is otherwise indistinguishable from a benign
   self-collision by exception shape.

**The four things the pending review MUST confirm** (recorded verbatim in intent, so the pending
review has its criteria):

1. the sentinel's expiry is **family-scoped, not auth-code-scoped**, so it outlives any successor;
2. the **deterministic key** preserves `RevokeFamilyAsync` idempotency with **no unbounded row
   growth**;
3. the sentinel **can never be redeemed** (empty payload, `Revoked` status);
4. the confirming `FindByHandleAsync` re-read is **itself fail-closed** — its own faults propagate and
   are never swallowed.

**Cost accepted in the design.** One extra write per family revocation. Revocation is a cold, rare,
reuse-triggered path and the write is idempotent, so this is accepted as the cost of closing the gap
without a new interface method or a second storage concept.

### 3.7 Residual risks accepted for this store, independent of any single item

- **The CAS atomicity invariant is irreducible.** The CLR cannot prove a given backend's
  `TryMarkConsumedAsync` is atomic. Mitigated by mapping guidance and the conformance kit, not
  eliminated — the same shape as the authorization-code store's insert-if-absent ceiling.
- **Family-revocation completeness is complete by construction only on a *queryable* store.** The one
  way to break it is a drifting secondary index on a non-queryable backend; that is kept off the
  sanctioned path and pinned by the conformance kit's mid-revoke-insert case.
- **Larger, longer-lived cleartext surface than the authorization-code store.** Six non-secret columns
  in clear versus one, sitting at rest for **months** rather than seconds-to-minutes. Assessed and
  signed off under §3.1b.
- **`RevokeBySubjectAsync` is a capability, not a shipped feature.** It exists on the grant store so a
  future logout-all is possible; the endpoint that would call it is **explicitly deferred**, no
  coordinator method invokes it. Do not mistake the column/method for a delivered logout-all.

---

## 4. Unified startup verification

The relevant trust boundary is the **credential-redaction guarantee**: no startup check may log
through a shadowed, non-redacting `ISanitizingLogger<>` before the shadow is detected and startup
aborted. Before this work that guarantee rested on registration order plus a code comment.

### 4.1 Security review amendments required before merge — PR #443 (issue #441), 2026-08-16

Security review of the design **required these amendments before merge**; all were made:

- **Verifiers are resolved after the gate phase**, not constructor-injected — so no verifier
  *constructor* can log first. (`ISanitizingLogger<T>` is deliberately public so out-of-package
  providers can inject it, which makes "log from a constructor through a shadowed sanitizer" a
  reachable path, not a theoretical one.)
- **The gate and its scanner move into core** and are registered by the **same
  `AddZeeKayDaAuthCore()` call as the runner** — closing the empty-gate-collection gap. Without this,
  a host that reaches a fully-wired signing configuration without ever calling `AddZeeKayDaAuth()`
  gets an **empty gate collection**, phase 1 passes **vacuously**, and phase 2 begins resolving and
  logging through unverified `ISanitizingLogger<T>` instances.
- **The exception wrapper names `ex.GetType().FullName`, never `ex.Message`.** An arbitrary exception
  message is untrusted text that may carry credential material (a Key Vault `RequestFailedException`
  carrying a SAS-bearing URI; a third-party verifier that interpolated a secret into its own
  exception). `ZeeKayDaConfigurationFailure.Message` is a plain public-API string that **neither**
  `SecretSanitizingLogger`'s key-based redaction **nor** `RedactedExceptionWrapper` can reach, and the
  host's own unhandled-startup-exception logger is not a sanitizing logger at all — so copying the
  message in would route credential material around **both** controls.
- **A thrown `ZeeKayDaConfigurationException`'s failures are absorbed verbatim**, not flattened to
  `startup.verifier_failed` — flattening would silently break operator alerting keyed on the stable
  `Code` of a security control (`signing.self_test_failed`,
  `logging.sanitizing_logger_shadowed`).
- **The gate is a same-change requirement of the runner's implementation issue**, not a later step.

**Architect confirmation of both security amendments**, same date, added three follow-on corrections:
the gate move adds **no `PackageReference`** to core and is a namespace-only relocation of two
`internal` types; the unwrap rule gains the structural argument that `AggregatedFailures` is non-empty
by construction, so absorbing can never become a silent swallow, **plus an
`OperationCanceledException` rethrow** so an orderly host shutdown is not reported as
`startup.verifier_failed`.

### 4.2 Security review of PR #450 (issue #444) — analyzer gap closed, 2026-08-16

`ZEEKAYDA0002` (the interpolated-string analyzer) was **extended with a symbol-based branch** so it
now rejects a non-constant `messageTemplate` passed to `StartupVerificationContext.AddWarning`,
closing a gap that had previously been recorded as open. The symbol-based branch matches `AddWarning`
by containing type and then its `messageTemplate` parameter by name/ordinal — necessary because
`AddWarning`'s *first* string argument is `code`, not the template.

**Scope limit of that fix.** The analyzer project is `IsPackable=false` and reaches the framework only
by `ProjectReference`, so **this extension binds first-party verifiers only**. The third-party limit
in §4.3 is unchanged by it.

*Correction preserved from the same review:* the relevant rule is **`ZEEKAYDA0002`, not
`ZEEKAYDA0001`** as an earlier revision stated. The CI log-hygiene grep already covered `AddWarning`
independently (it matches sensitive placeholder names as plain text in any `.cs` file under `src/`).

### 4.3 Residual limits and explicit negatives recorded with this design

**Scope limit of the redaction guarantee — this is the form in which the criterion was accepted.**
The guarantee covers **the verification subsystem only**: no `IStartupVerifier` and no runner log call
can precede the gate. It does **not** extend to arbitrary host or third-party `IHostedService`
registrations, which a host may register before the runner and which
`HostOptions.ServicesStartConcurrently = true` may run concurrently with it. That limit is unchanged
from the prior design and was **out of scope** — which is precisely why the criterion is read as
"structurally guaranteed **for the framework's own startup checks**", a claim this design achieves and
the old registration-order convention did not.

**`internal` is a correctness boundary here, not a security boundary.** Making the gate collection
unreachable outside the framework means a third party cannot claim a position ahead of the
sanitizing-logger check (the priority-gaming risk a public ordering knob would leave open). But these
assemblies are **not strong-named**, so `InternalsVisibleTo` matches on simple assembly name alone: an
assembly that names itself `ZeeKayDa.Auth.AspNetCore` would receive gate access. That requires an
attacker who can already place an assembly in the host's load path, at which point the host is
compromised regardless — so it is **not** a reason to adopt strong naming, but it **is** why `internal`
is treated as a boundary against accidental misuse and API-surface creep, not against a hostile
assembly.

**`IStartupVerifier` is not a sandbox.** A third-party verifier runs inside the host's startup with
full DI access. What the design guarantees is that it cannot run before the gate, cannot suppress or
observe another verifier's findings, cannot influence execution order, and cannot fail silently. It
**can** still hang startup (accepted — a hanging verifier hangs a host that is not yet serving
traffic, which fails closed) and can do anything a DI-resolved singleton can do.

**The logging chokepoint guarantees routing, not content.** Three residual limits, accepted:

1. an author who interpolates a secret directly into the template string bypasses by-key redaction
   exactly as with a raw `ILogger` call — the binding rule for verifier authors, first- **and**
   third-party, is that secret material and a caught exception's `Message` belong in neither the
   template nor a non-sensitive-keyed arg;
2. **`AddFailure` is deliberately left uncovered** by the analyzer — its message lands in a
   `ZeeKayDaConfigurationFailure` on public API surface rather than in a log record, by-key redaction
   never applies to it, and it is governed instead by the rule that a caught exception's `Message`
   never reaches it;
3. a third-party verifier's template is author-controlled and is logged as-is, **newlines included**,
   so **log forging via a verifier message is available to anyone who can already register a
   verifier** — a low bar, and one more entry on the "not a sandbox" list.

*Why the structured shape is load-bearing, not stylistic:* an earlier draft flattened the message at
the `AddWarning` call site, which would have stripped the very keys redaction keys on and quietly
downgraded the guarantee. `AddWarning` takes a **message template plus args** so both by-key redaction
and `RedactedExceptionWrapper` still apply end to end.

**Restart-loop side-effect cost of aggregation — accepted, not mitigated.** Under phase-2 aggregation
a host already known to be misconfigured still executes `ClientRepositoryActivationVerifier` (PBKDF2
over every configured client secret — cost linear in client count and deliberately expensive per
secret) and the signing self-test (a real Key Vault sign operation plus key reads). In a
`CrashLoopBackOff` deployment that repeats indefinitely: sustained CPU burn and sustained request
volume against a vault that enforces per-vault throttling. It is **self-inflicted rather than
attacker-driven** and bounded by the host's own restart backoff, which is why it is accepted rather
than mitigated by a "skip side effects once failures exist" rule — that rule would reintroduce exactly
the inter-verifier dependency the design removes.

**Two things keep it small and are to be treated as binding:** side-effecting verifiers are registered
**last**, after the cheap configuration checks; and **no verifier retries internally.**

**No silent swallow, deliberately.** There is no `catch`-and-continue path and no "log the exception
and carry on" mode: a check that could not complete is indistinguishable from a check that failed, and
both must fail closed. This matters most for side-effecting verifiers — a signing self-test or a
client-repository activation that throws must never be interpreted as "passed."

**Aggregation weakens no individual check.** Phase 2 changes *when* the exception is thrown, never
*whether*. No verifier gains the ability to downgrade its own failure to a warning; `AddFailure` and
`AddWarning` are distinct calls. A warning's `level` is a per-call-site choice by the check's author,
**not a runtime knob an operator or third party can turn down**, and the runner has no suppression
path.

---

## 5. Open items carried out of this extraction

Everything below was recorded in ADR prose as pending, uncovered, or undischarged. Each is now
tracked by an issue, because a line in this file does not survive as a task. Do not read the
existence of shipped code as approval for any of them.

- **§3.6 — the zero-row-family revocation sentinel is PENDING, not signed off** (#485). The design
  was approved; the shipped implementation has never been reviewed. Its review criteria are recorded
  in §3.6 so the pending review can be executed against them.
- **§1.5 — the per-handoff signing self-test is covered by no sign-off** (#487). It was added to the
  signing path after both signing-key reviews completed.
- **§2.1 — the plaintext `FamilyId` sign-off is predicated on conditions in unbuilt code** (#488).
  The token endpoint must mint a fresh CSPRNG `familyId` per authorization code; it is still a stub,
  so the premise the approval rests on is not yet satisfied.
- **§3.x — a non-blocking overflow note was only half discharged** (#486). One of the two expiry
  arithmetic call sites is guarded; the other is not.
- **§1.3 — retired private-key memory residency on `KeySetOptions` is bounded only by request
  cadence** (#489). Residual accepted; the noted scavenge-timer mitigation was never filed.
- **§1.3 — the active-key-expires-with-no-successor gap has no operator-facing surface** (#490).
  Recorded as something "operators should be aware of", with nothing for them to be aware from.

*Unverifiable anchor:* the round-2 Azure Key Vault sign-off in §1.2 is anchored to commit `ea5c9b1`,
which no longer resolves — the branch commit did not survive squash-merge. The record is preserved
verbatim, but that SHA cannot be checked out.

---

## 6. Corrections

Appended, never applied in place. A sign-off record is only useful if the gap between what was
approved and what shipped is itself visible — silently editing an old entry to match reality would
erase exactly the fact worth keeping.

### 6.1 §4.3's side-effecting-verifier ordering mitigation was never implemented

**Discovered 2026-08-21, while migrating the startup-verification design into the register.**
Tracked by **#499**.

§4.3 records, as the mitigation that made an accepted residual acceptable:

> side-effecting verifiers are registered **last**, after the cheap configuration checks, so a
> configuration failure is discovered before the expensive work

Neither half holds against shipped code.

**The side-effecting verifier is registered first.** `SigningStartupSelfTestVerifier` — which
performs a real signing operation, including a remote call on a Key Vault provider — is registered
by `AddZeeKayDaAuthCore()` (`ZeeKayDaAuthCoreServiceCollectionExtensions.cs:68`).
`AddZeeKayDaAuth()` calls that at `ZeeKayDaAuthServiceCollectionExtensions.cs:64`, *before* the
cheap verifiers at `:107`–`:115`. The runner iterates in registration order, so the expensive check
runs first. The code comments at `:96` that "no ordering dependency exists here", which is the
opposite of what the sign-off relies on.

**And ordering could not have helped.** Phase 2 runs every verifier regardless of earlier failures,
accumulating into a list and throwing only after the loop
(`StartupVerificationHostedService.cs:58`, `:80`). There is no early exit. The aggregate-all model
was a later deliberate decision, and it made the ordering mitigation inoperative rather than merely
unimplemented.

**Status of the residual:** it stands **unmitigated**, not accepted-with-mitigation as §4.3 reads.
The direct impact is low — it fails closed, and the work is a self-test rather than anything
attacker-triggerable — but a misconfigured application on a Key Vault provider performs a remote
signing call on every startup. #499 decides between accepting the residual honestly and giving the
runner real cheap-then-side-effecting phases.

**Why this is recorded here rather than fixed in §4.3:** the original text is the evidence of what
the reviewer believed they were approving. That belief, and its divergence from the code, is the
audit-relevant fact.
