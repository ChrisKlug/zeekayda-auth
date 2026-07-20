# ADR 0015 — Signing-Key Provider: KeySet / KeySource Tiers and the Data-Not-Objects Contract

**Status:** Accepted (security approve-with-conditions; both must-fix conditions resolved and should-fix
notes folded in — see "Security Considerations" and the changelog)
**Date:** 2026-07-20 (issue #418; security conditions resolved 2026-07-21)

> **Relationship to ADR 0011.** This ADR **supersedes** the following parts of
> [ADR 0011](./0011-signing-key-management.md): the three-tier options hierarchy (§3.4), the
> external-provider rotation contract (§3.5), the parts of the provider abstraction that had a
> provider return a live `SigningKeySet` of disposable key objects (§3.2's `LoadKeysAsync` /
> `HasKeySetChangedAsync` / `SignInputAsync` / reuse-guards), and the *timing* of retired-private-key
> destruction (§3.3(c), relaxed here). It does **not** restate or change everything else ADR 0011
> settles — read ADR 0011 for all of the following, which apply here **unchanged**: the two-method
> `IJwtSigningService` consumer contract and `SigningResult` (§1); `alg:none` being unrepresentable
> and header/`kid`/`alg` consistency by construction (§1); the derived `RetirementWindow` and its
> security sign-off (§3.3(a)/(a′)/(b)); the development-key environment gate (§2); minimum key
> strength and PEM file hardening (§2); `IJwksDocumentProvider` and the single-flight-gated JWKS read
> path (§4.3); `JwkThumbprint`, and the public-vs-internal helper split (§4.4/§4.5); the NuGet
> packaging model (ADR 0012). Where ADR 0011 §3.2/§3.4/§3.5 and this ADR disagree about *what a
> provider implements*, this ADR governs.

---

## Context

ADR 0011 §3.4/§3.5 (issue #409) unified File, PFX, Windows Certificate Store, and Azure Key Vault
(cached and remote) under one `RotatingKeySourceOptions` contract with a single
`KeyRotationCheckInterval`. Issue #418 found that unification does not hold: the split was cut on
*"does the source reload?"*, which forces two genuinely different models to share one property that
means two different things —

- **Key Vault** *self-discovers*: it polls a remote store whose version list genuinely changes
  between calls, and `KeyRotationCheckInterval` is a real external poll cadence and kill-switch
  reaction time.
- **File / PFX / Windows Certificate Store** are a *fixed list known at config time*: nothing changes
  at runtime except the wall clock crossing each key's activation instant, and
  `KeyRotationCheckInterval` is only an internal clock-tick over a pre-configured timeline.

Every doc fix (PR #415, the two review corrections logged in ADR 0011's changelog) had to re-explain
"this property means X for Key Vault but Y for File/PFX/cert-store." That per-provider caveating is
the symptom of a shared contract describing two things, not one.

This ADR reverses the #409 unification and re-cuts the split on the axis that actually differs:
**how keys are acquired and what drives activation.** It also takes the opportunity — since nothing
has shipped to a real consumer (the options are `*Added in Unreleased*`) — to fix the deeper problem
underneath the options naming: providers hand back **live bundles of disposable private-key objects**
(`SigningKeySet`/`SigningKeyPair`), which forces the base class to carry reuse-guards, ask/refresh
change-detection, and re-materialisation machinery whose whole job is to police mistakes a provider
can only make *because* it holds key objects. We remove the ability to make those mistakes.

---

## Current State

### 1. Two production tiers, cut on acquisition + activation-driver

The base type `JwtSigningServiceOptions` (empty; never derived from directly) is retained from
ADR 0011. The `StaticKeySourceOptions` / `RotatingKeySourceOptions` split is **removed** and replaced
by two tiers cut on a different axis:

```csharp
namespace ZeeKayDa.Auth.Tokens;

/// <summary>Shared base. Empty. Never derived from directly.</summary>
public abstract class JwtSigningServiceOptions { }

/// <summary>
/// Tier A. The complete, fixed set of keys is supplied at configuration time and never changes at
/// runtime; the only thing that advances is the wall clock crossing each key's ActivateAt.
/// </summary>
public abstract class KeySetOptions : JwtSigningServiceOptions
{
    /// <summary>
    /// How long before a key's ActivateAt its public half must already be published in the JWKS.
    /// Advisory on this tier: the operator owns activation timing (via each key's ActivateAt), and
    /// the base class only surfaces a startup warning (HasTooSoonPendingActivation) when a key's
    /// ActivateAt is nearer than this. Replaces ADR 0011's AssumedJwksPropagationDelay.
    /// </summary>
    public TimeSpan PublicationLead { get; set; } = TimeSpan.FromHours(1);
}

/// <summary>
/// Tier B. The provider re-supplies the current key list on a cadence; the list genuinely changes
/// between calls because something else owns the keys and the provider reads them.
/// </summary>
public abstract class KeySourceOptions : JwtSigningServiceOptions
{
    /// <summary>How often the base class re-asks the provider for the current key list.
    /// One meaning only: re-ask cadence. Replaces ADR 0011's KeyRotationCheckInterval.</summary>
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// How long before a key's ActivateAt its public half must already have been published. Enforced
    /// entirely through durable, ActivateAt-derived timing: the base treats PublishAt = ActivateAt −
    /// PublicationLead as the instant the key's public half must already be in the JWKS (see §3), and
    /// the provider maps its store's durable timestamp onto ActivateAt so that lead is satisfied
    /// (e.g. Key Vault: ActivateAt = CreatedOn + PublicationLead). It is NEVER derived from
    /// observed/first-seen time. Defaults to RefreshInterval when left unset. Invariant:
    /// PublicationLead >= RefreshInterval — a config-level relationship (the lead is at least one poll
    /// cycle), not per-key state. Replaces ADR 0011's SigningKeyActivationDelay.
    /// </summary>
    public TimeSpan PublicationLead { get; set; } // unset => resolves to RefreshInterval
}
```

**Tier assignment.**

- **Tier A (`KeySetOptions`)** — File (PEM), PFX, Windows Certificate Store. Development/in-memory is
  a trivial degenerate Tier A: one key, no `ActivateAt`, active from startup. **`StaticKeySourceOptions`
  retires entirely** — its sole consumer (`DevelopmentSigningKeyOptions`) becomes a `KeySetOptions`.
- **Tier B (`KeySourceOptions`)** — Azure Key Vault (cached and remote), a DB-backed table, a file-glob
  that *discovers new files at runtime*, remote signing (KMS/HSM).

The cut is on **whether the set is known up front**, not on whether it reloads. A single PEM file with
a pre-staged successor cert reloads on a schedule but its *set is fixed at config time* → Tier A. A
file-*glob* that grows new members at runtime → Tier B, because the list genuinely changes.

### 2. Provider contract — sources, not objects

Providers no longer build and return live `SigningKeySet` bundles of disposable key objects. On the
base class `JwtSigningService<TOptions>` (retained; still the only thing a provider derives from), the
single `LoadKeysAsync` abstract method is replaced by **two methods that return data and lend a signer
on demand**:

```csharp
public abstract class JwtSigningService<TOptions> : IJwtSigningService
    where TOptions : JwtSigningServiceOptions
{
    /// <summary>Returns the current listing — pure public metadata, never private material.
    /// Tier A: called exactly once, ever. Tier B: called each RefreshInterval.</summary>
    protected abstract ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(CancellationToken cancellationToken);

    /// <summary>Lends a signer for the key the base class has selected as active. The base class calls
    /// this ONLY for the currently-active key, owns the returned signer, and disposes it.</summary>
    protected abstract ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken);
}
```

```csharp
/// <summary>Pure public data describing one trusted key. No private material.</summary>
public sealed record KeyListing(
    KeyId Id,                       // the provider's own stable identifier (thumbprint, KV version id)
    SigningAlgorithm Algorithm,
    PublicKeyParameters PublicKey,  // public-only RSA/EC parameters
    DateTimeOffset? ActivateAt,     // null or past => active from startup (bootstrap)
    DateTimeOffset ExpiresAt);      // hard expiry (cert NotAfter); distinct from derived retirement

/// <summary>A lightweight wrapper over the provider's stable key identifier. NOT the JWKS `kid`.</summary>
public readonly record struct KeyId(string Value);

/// <summary>Public-only key parameters — the same public material ADR 0011's SigningKeyDescriptor
/// carried, minus kid/algorithm (those live on KeyListing). Constructed from RSAParameters (public)
/// or ECParameters (public).</summary>
public sealed record PublicKeyParameters { /* SigningKeyType KeyType; RSAParameters?; ECParameters? */ }

/// <summary>Produces signature bytes over a formed signing input. One behavioural method; async so a
/// remote signer (KV/KMS/HSM) can make a network round trip. This is ADR 0011's SignInputAsync
/// default/override split re-expressed as an object.</summary>
public interface ISigner : IDisposable
{
    ValueTask<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default);
}

/// <summary>Shipped BCL implementation over RSA/ECDsa. Local providers construct this and never
/// implement ISigner themselves. Only genuinely remote providers implement ISigner.</summary>
public sealed class LocalSigner : ISigner { /* wraps RSA/ECDsa; delegates to internal SigningAlgorithms.Sign */ }
```

Consequences that fall out of "data, not objects":

- **`KeyListing` carries no `kid`.** The base derives the public `kid` via `JwkThumbprint.Compute(PublicKey)`
  (ADR 0011 §4.4). ADR 0011's rule "a `kid` MUST NOT be a raw external identifier" (Key Vault URI,
  X.509 thumbprint) becomes **structurally enforced**: a provider supplies only its internal `KeyId`
  and the public key, and cannot express a leaking `kid` because it never supplies the `kid` at all.
- **The base requests private material only for the active key.** `CreateSignerAsync` is called only
  for the selected active key; the base never asks for a non-active, future, or retired key's private
  material. Whether that material is *actually* held out of process memory is then a **provider
  obligation, not a structural guarantee** — a provider over a bundled format (PFX, a Windows
  Certificate Store entry) reads the whole thing, private half included, when it reads the file at
  all, so "non-active private material is never resident" holds only if that provider extracts the
  public listing without retaining the private material until `CreateSignerAsync` asks for the active
  key's. `implement-custom-signing-provider.md` MUST state this obligation for bundled-format
  providers (trackable into the how-to follow-up).
- **`LocalSigner` collapses the default/override split.** Local providers (development, File/PEM, PFX,
  Windows Certificate Store) build a `LocalSigner` in `CreateSignerAsync`. A remote provider (KV
  remote signing, KMS, HSM) returns its own `ISigner` whose `SignAsync` is a network call — the
  private key never becomes local.
- **The two reuse-guards in `JwtSigningService.BorrowSetAsync` are DELETED.**
  `FindReusedPrivateKeyKid` and the "same `SigningKeySet` instance returned twice" check exist only
  because a provider used to hand back private-key *objects* it could accidentally alias across two
  sets. An implementer never holds a key object now, so both mistakes become **unrepresentable** —
  the same structural-fix principle as issue #355's active-key reshape. The guards, and the
  `SigningKeySet`/`SigningKeyPair` types themselves, are removed.
- **`ISigner.Dispose` MUST release only its own per-activation handle.** The base disposes the
  `ISigner` each time the active key changes. A remote `ISigner` (KV/KMS) that references a shared,
  DI-owned SDK client MUST NOT tear that client down on `Dispose` — it disposes only whatever local
  handle or copy it introduced. This is a normative contract on `ISigner`, not advisory prose.
- **Duplicate-`kid` rejection still runs — now on the derived thumbprints.** The base computes each
  listing's `kid` via `JwkThumbprint.Compute(PublicKey)` at `ListKeysAsync` time and rejects a
  listing set that yields duplicate `kid`s with `ZeeKayDaConfigurationException` (ADR 0011 §4.3),
  alongside the key/algorithm-compatibility and key-strength checks (§7). The chokepoint moves from
  ADR 0011's load path to `ListKeysAsync`, but the invariant is unchanged.

### 3. One shared timeline engine, unchanged

`SigningKeyRotation` (the existing public static class over `RotationKey(Id, ActivatesAt, ExpiresAt)`
→ `BuildActivationTimeline` / `SelectActiveKey` / `SelectIncludedKeys` / `HasTooSoonPendingActivation`)
is already the right engine and is reused **essentially unchanged** as the single engine both tiers
call. Each tier maps its listings onto it identically:

```
RotationKey.Id         = KeyListing.Id.Value
RotationKey.ActivatesAt = KeyListing.ActivateAt ?? DateTimeOffset.MinValue   // null/past => eligible from startup
RotationKey.ExpiresAt  = KeyListing.ExpiresAt
```

Derived quantities (operator sets **only** `ActivateAt` per key):

- **`RetirementWindow`** stays derived exactly as ADR 0011 §3.3 (never operator-set).
- **`PublishAt = ActivateAt − PublicationLead`** — derived; feeds the too-soon check, never operator input.
- **`DeactivateAt = successor.ActivateAt + RetirementWindow`** — derived; this is exactly the
  `RotationEntry.RetiredAt + RetirementWindow` window `SelectIncludedKeys` already computes.

A too-short retirement window is therefore **unrepresentable** — there is no operator deactivation-date
knob to get wrong. (Confirmed resolution of ADR 0011's open deactivation-date question: derived, not
configurable.)

The Key-Vault-specific `firstEverVersion` bootstrap exemption is no longer engine logic: the Key Vault
provider encodes it in the data by setting `ActivateAt = null` (or its `CreatedOn`) for the
chronologically-first version and `CreatedOn` for later versions, so the shared engine's ordinary
"eligible from startup" handling covers it with no `firstEverVersion` special case. The single-key
bootstrap exemption in `SelectActiveKey` is retained as-is.

### 4. State model — immutable snapshot + lazy selection

The base class holds an immutable snapshot of the public `KeyListing`s plus the precomputed timeline,
and exactly **one** live `ISigner` (the active key's). Active-key and JWKS selection are computed
**lazily per request** from the snapshot's timeline and `now` via `SigningKeyRotation` — a pure
function over immutable public data.

- **Tier A (`KeySetOptions`):** `ListKeysAsync` runs **once**; the snapshot is built once and never
  swapped. No lock, no refcount, no single-flight, no re-materialisation. `CreateSignerAsync` is
  called only when the computed active `KeyId` changes (wall clock crossing a successor's
  `ActivateAt`). All signers are disposed at process shutdown.
- **Tier B (`KeySourceOptions`):** the snapshot is swapped on each refresh; this is the **only** tier
  that keeps swap + borrow/return machinery, and only for safe disposal of a superseded active signer.
  It is much smaller than today: `ListKeysAsync` is a cheap public-metadata call, so **the
  `HasKeySetChangedAsync` ask/refresh split retires** — the expensive operation
  (`CreateSignerAsync` / private-key acquisition) is now naturally gated on the active `KeyId`
  changing, which the base computes directly from the cheap listings. The whole-set change-detection
  machinery (`ToChangeDetectionSet`, the three-field `(Version, Enabled, IsActive)` tuple, the
  write-only-on-load baseline) is removed with it.

### 5. Disposal — the base loads private material only for the active key (option (a), accepted)

Because `CreateSignerAsync` is called only for the active key, the base never requests private material
for a non-active/future/retired key. This improves on ADR 0011 §3.3(c)'s "destroy retired private
material promptly" — but note the limit made explicit in §2: for a **bundled format** (PFX,
cert-store) that yields the whole key when read, keeping non-active private material out of process
memory is a **provider obligation**, not something the contract structurally guarantees.

For the **previously-active** signer at a handoff, Tier A's lazy recompute disposes it **opportunistically**
when the computed active `KeyId` changes on the next request — bounded by request cadence, falling back
to shutdown if the process goes idle at the handoff instant. This is a **relaxation** of ADR 0011
§3.3(c)'s "immediately on retirement" to "shortly after, bounded by request cadence; the retiring
signer's private material is reclaimed on the next recompute or at shutdown." Security **accepted this
relaxation as-is**. To bound the idle-app worst case (a retired key's private `ISigner` resident until
shutdown if no request arrives at the handoff), an **optional** Tier A scavenge timer that recomputes
active-key selection and disposes a superseded signer on a low-frequency tick **may** be added — it is
a noted possibility, not a requirement, and is trackable into the follow-up implementation issues.
Tier B disposes the superseded signer after in-flight `SignAsync` calls complete, per ADR 0011 §3.2's
ordered-disposal rule.

### 6. No `Enabled` flag — omission is the kill switch

There is **no** `Enabled`/disabled flag anywhere in the options or the contract. A Tier B provider
returns a key for exactly as long as it should be trusted — including through its retirement window.
A key that **stops appearing** in the returned listing is dropped from the JWKS on the next refresh,
immediately, retirement window or not.

- **Normal rotation:** Key Vault / a DB naturally keep old versions / rows, so a retiring key keeps
  appearing until its derived retirement window closes.
- **Emergency kill:** revoke / disable / delete the key in the backing store ⇒ the provider's next
  `ListKeysAsync` stops returning it ⇒ it is gone on the next poll. Key Vault's `Enabled=false`
  collapses into **"the Key Vault provider lists enabled versions only."**

**Omission must not be an overloaded signal.** A vanish from a listing could otherwise mean three
indistinguishable things — a key legitimately aged past its window, a key accidentally dropped early,
or a provider that failed to read its store completely. The contract disambiguates all three:

1. **Post-window vanish — expected, silent.** A key that stops being listed *after* its derived
   retirement window has closed is the normal end of life. No log beyond routine.
2. **Within-window vanish — dropped, but `Warning`.** A key that stops being listed *while still
   inside its derived retirement window* is still dropped from the JWKS on the next refresh (the kill
   switch still fires — this is what makes emergency revocation immediate). But the base **MUST emit a
   `Warning`**: this is the accidental-omission / vanished-`kid` detector, and it is the one genuine
   capability the old Key Vault model had that a naive kill-by-omission would lose. This signal
   **MUST NOT** be downgraded to info/observability; it stays at `Warning`. It is the price of dropping
   the explicit `Enabled` flag, and it is preserved deliberately.
3. **Failed or partial read — throw, never drop.** `ListKeysAsync` carries a **completeness
   contract**: a provider that cannot produce a *complete* read of its current key set **MUST throw**
   (fail closed, per ADR 0011 §3.2), never return a short or partial list. A partial read **MUST NOT**
   be interpretable as "these keys were killed." This closes the failure mode where a transient store
   error silently revokes every key it failed to enumerate.

Given (1)–(3), a Tier B provider MUST keep returning a retiring key until its derived retirement window
closes; the normal KV/DB pattern of keeping old versions/rows satisfies this automatically, and any
accidental early omission is caught loudly by (2) rather than passing silently.

Consequence for the Key Vault package: its parallel `KeyVaultSigningKeyRotation` (which existed mainly
to track `Enabled` and detect vanished-`kid` anomalies) **largely folds into the shared engine** —
`Enabled=false` collapses into "the Key Vault provider lists enabled versions only," and the
vanished-`kid` detection is now the shared within-window `Warning` of (2) above, kept at `Warning`, not
removed.

### 7. Algorithm handling — unchanged in spirit, now all on public data

Algorithm is declared per-provider (applied across certs) or derived where the key determines it
(EC P-384 → ES384), and carried on `KeyListing.Algorithm`. The base runs today's
`SigningAlgorithms.ValidateKeyAlgorithmCompatibility` and `ValidateKeyStrength` over **every listing
at `ListKeysAsync` time**. Key type, EC curve, and RSA modulus size are all readable from the public
key, so **all** of ADR 0011 §1/§2's load-time validation now runs on public data *before any private
material is loaded*. Mixed key types across a set are allowed provided each key is internally
consistent; the active signer's algorithm is the one written to the JWS header.

### 8. Third-party tier-choice litmus + how-to decision guide (resolves Q4)

> **Do you own the full list of keys up front? → `KeySetOptions`.
> Does something else own the keys and you read them? → `KeySourceOptions`.**

`docs/how-to/implement-custom-signing-provider.md` gains a "Which tier do I implement?" decision guide
built on that litmus (the two shapes — "a static list from a location" vs "a backend that changes
under me and I re-read it" — are intuitively easy to pick between; custom implementations are expected
to be rare, so the two-tier choice is an accepted, minor cost over one shared contract). The doc
rewrite is follow-up implementation work (the current page documents the retiring
`StaticKeySourceOptions`/`RotatingKeySourceOptions` tiers and is superseded wholesale).

### 9. Migration — clean break, no deprecation (resolves Q5)

There are no shipped consumers (the tiers and properties are `*Added in Unreleased*`), and the repo
owner authorised a clean reshape. This is a **breaking replacement, not a deprecation path**.
Removed/replaced: `RotatingKeySourceOptions`, `StaticKeySourceOptions`, `KeyRotationCheckInterval`,
`SigningKeyActivationDelay`, `AssumedJwksPropagationDelay`, `SigningKeySet`, `SigningKeyPair`,
`LoadKeysAsync`, `HasKeySetChangedAsync`, `SignInputAsync`, and the `BorrowSetAsync` reuse-guards.
Existing docs (`rotate-signing-keys.md`, `implement-custom-signing-provider.md`, and the per-provider
how-tos) may be rewritten from scratch. **PR #415 (issue #407) stays parked** as a valid narrower fix;
it neither blocks nor is blocked by this ADR.

### 10. Emergency-rotation docs (resolves Q6)

Once this lands, `rotate-signing-keys.md`'s "Emergency key rotation" section no longer caveats by
provider mid-paragraph, because the two abstractions finally match two real procedures:

- **Tier A (File/PFX/cert-store):** remove the compromised key from configuration, redeploy, restart
  (a cold start rebuilds the single snapshot). No enable/disable flag exists — none is needed.
- **Tier B (KV/DB/KMS):** revoke/disable/delete in the backing store so the provider's next
  `ListKeysAsync` stops returning it; effective on the next poll (bounded by `RefreshInterval`), or
  immediately on restart. Kill-by-omission is the single mechanism; there is no separate `Enabled`
  concept to describe.

Neither procedure retroactively invalidates tokens a relying party already accepted before rotation —
that residual window is bounded by the relying party's own JWKS-cache TTL, unchanged from ADR 0011.

---

## Considered and Rejected Alternatives

### Keeping the #409 unified `RotatingKeySourceOptions` (the reversal this ADR records)

**Rejected — this is the decision being reversed.** #409 (ratified less than two weeks earlier, PR
#413/#414) cut the split on *"does the source reload?"* and gave every rotating provider one
`KeyRotationCheckInterval`. It did not hold because File/PFX/cert-store and Key Vault do not share one
underlying model — they shared a *name* for two different things: an internal clock-tick over a fixed,
pre-configured timeline (Tier A) versus a real external poll cadence and kill-switch reaction time
(Tier B). The evidence was concrete and repeated: every documentation fix (PR #415 and the two review
corrections in ADR 0011's changelog) had to say "this means X for Key Vault but Y for File/PFX." A
shared contract that can only be documented by per-provider caveats is describing two things. #409's
later splitting-out of `SigningKeyActivationDelay` (KV) and `AssumedJwksPropagationDelay` (File/cert)
was already a partial admission of this; this ADR finishes the job by splitting the *tier itself* on
the axis that genuinely differs (acquisition + activation-driver) rather than patching around a shared
poll property. **A future reader considering re-unifying these tiers should stop here:** the unification
was tried, ratified, and reversed for this reason.

### "Active cert + optional next cert with a cutover date" for Tier A (Q2)

**Rejected in favour of an ordered list of keys each with its own `ActivateAt`.** The
mandatory-active-plus-optional-next shape covers the common case but not a pre-staged chain of more
than two certs, and it introduces a second way to express "which key is active" (positional/optional)
that the ordered-listing-plus-`ActivateAt` model expresses once, uniformly, and shares with Tier B via
the same `SigningKeyRotation` engine. An ordered `KeyListing` list needs no special "next" slot and no
separate cutover concept — `ActivateAt` per key *is* the cutover. Tier A needs **no** periodic-recheck
knob: reacting to a file mtime change, or discovering new files, is either a restart concern (fixed
set) or a Tier B concern (a genuinely changing set) — not a shared Tier A property.

### Keeping `HasKeySetChangedAsync` / the whole-set change-detection tuple

**Rejected — subsumed structurally.** The ask/refresh split (ADR 0011 §3.2, issues #334/#347/#348/#349)
existed to avoid re-downloading *private key material* on a poll where nothing rotated. In the
data-not-objects model `ListKeysAsync` returns only public metadata and the expensive step
(`CreateSignerAsync`) is called *only* when the active `KeyId` changes — which the base computes
directly from the cheap listings. The optimisation the ask hand-rolled is now the default behaviour, so
the hook, its three-field comparison tuple, and its write-only-on-load baseline discipline are all
removed rather than ported.

### An `Enabled`/disabled flag on the contract (instead of kill-by-omission)

**Rejected.** An `Enabled` flag only ever meant "Key Vault version is enabled," and it forced the
shared abstraction to carry a concept three of four providers had no equivalent for (a File/cert
registration has no enable bit). Collapsing it into "the provider lists trusted keys only" makes
revocation uniform across every Tier B backing store (revoke/disable/delete → stops being listed →
gone next poll) and removes a bespoke, provider-conditional kill-switch from the shared contract. The
one capability the explicit flag had that naive omission would lose — telling an *accidental* early
drop apart from a legitimate aging-out — is preserved by the within-window-vanish `Warning` and the
`ListKeysAsync` completeness contract (§6), so omission is a three-state disambiguated signal
(post-window vanish silent / within-window vanish dropped-plus-`Warning` / failed read throws), not an
overloaded one.

### `PublicationLead` on the shared base instead of per-tier

**Rejected — and note this is deliberately *not* a repeat of the #409 mistake.** `PublicationLead`
lives on both `KeySetOptions` and `KeySourceOptions`, which superficially resembles the shared
`KeyRotationCheckInterval` this ADR is reversing. The difference is the reason the reversal was needed:
`KeyRotationCheckInterval` fused *two genuinely different concepts* (internal clock-tick vs external
poll cadence) under one name. `PublicationLead` is *one* concept — the publish-then-activate lead — on
both tiers; only its **enforcement** differs by the tier's activation driver (advisory startup warning
on Tier A where the operator owns `ActivateAt`; framework-derived `PublishAt` on Tier B where the
framework owns activation). One concept, tier-appropriate enforcement, is a genuine shared abstraction;
two concepts sharing a name was not. Putting it on the base anyway was rejected because Tier B needs the
`PublicationLead >= RefreshInterval` invariant, which is meaningless on Tier A (no interval), so a
base-level property would carry a validation rule that applies to only one subtype. (This is a flagged
review point — see "Security Considerations".)

---

## Consequences

### Positive

- **The two real procedures finally have two matching abstractions** — no more per-provider doc caveats
  (the exact rot #418 catalogued).
- **A provider cannot alias, reuse, or mis-order private key objects** — it never holds one. The #355
  reuse-guards and same-instance checks are deleted as unrepresentable.
- **Least-privilege key loading**: the base requests private material only for the active key;
  non-active/future/retired keys are only ever asked for in public form (keeping them out of memory is
  then a provider obligation for bundled formats — §2/§5).
- **Kid-leak resistance is structural**: the provider cannot supply a raw external identifier as `kid`,
  because it never supplies the `kid`.
- **Tier A has near-zero machinery** (one snapshot, no locks/refcounts/single-flight); Tier B is much
  smaller than today (no ask, no re-materialisation, no reuse-guards).
- **Revocation is uniform across every Tier B store** via kill-by-omission.

### Negative / Trade-offs

- **A breaking reshape of a two-week-old, already-ratified design.** Accepted because nothing shipped
  and the abstraction quality gain is large (issue #418's explicit authorisation).
- **Retired-private-key destruction is relaxed from "immediately" to "bounded by request cadence"** on
  Tier A (§5) — security accepted this as-is; the base never requests non-active private material, and
  an optional scavenge timer can bound the idle-app worst case.
- **The Tier B early-drop case** (§6) is handled by a `Warning` (within-window vanish) plus a
  `ListKeysAsync` completeness-MUST (failed/partial read throws), not left as an unguarded footgun —
  accepted over an `Enabled` flag, which would reintroduce the provider-conditional concept this ADR
  removes while covering less (no delete/purge, no DB/KMS store).
- **New public type surface** (`KeySetOptions`, `KeySourceOptions`, `KeyListing`, `KeyId`,
  `PublicKeyParameters`, `ISigner`, `LocalSigner`) is a SemVer commitment — offset by the removal of
  `SigningKeySet`/`SigningKeyPair`/`LoadKeysAsync`/`HasKeySetChangedAsync`/`SignInputAsync`.
- **Third parties choose a tier** rather than implementing one shared contract (Q4) — accepted; the
  litmus makes the choice a one-liner and a decision guide is added.

---

## Security Considerations

Security reviewed this ADR on PR #419 and returned **approve-with-conditions**; Chris adjudicated, and
the conditions below are now folded into the current-state sections above. This section records the
trust-boundary items and how each was resolved (issue #418 flags this ADR `area:security`, since PR
#415's review found the superseded abstraction's docs factually wrong twice):

1. **Kill-switch-via-omission semantics (§6) — resolved.** Revocation is uniform: a key stops being
   trusted when the provider stops listing it (revoke/disable/delete → gone next poll, bounded by
   `RefreshInterval`, or immediately on restart), which is *stronger and more uniform* than ADR 0011's
   `Enabled` kill-switch (it also covers delete/purge and DB/KMS stores with no `Enabled` bit).
   **Condition 2 fix:** omission is disambiguated into three states — post-window vanish (silent),
   within-window vanish (dropped **plus a `Warning`**, the accidental-omission / vanished-`kid`
   detector, kept at `Warning`, never downgraded), and failed/partial read (`ListKeysAsync`
   **MUST throw**, never return a short list a partial read could be mistaken for a kill). This
   preserves the one capability the explicit `Enabled` flag had that naive omission would lose.

2. **The §3.3(c) disposal relaxation (§5) — accepted as-is.** The base requests private material only
   for the active key; the previously-active Tier A signer is disposed opportunistically on the next
   active-`KeyId` recompute ("bounded by request cadence, reclaimed on next recompute or at shutdown"),
   not "immediately." An **optional** scavenge timer is noted to bound the idle-app worst case.
   (Overstatement corrected per should-fix: keeping non-active private material out of memory is a
   provider obligation for bundled formats, not a structural guarantee — §2/§5.)

3. **Fallback availability during the `PublicationLead` window — no fail-closed gap.** While a rotated-in
   key is published-but-not-yet-active, the **prior active key stays active** until the successor's
   `ActivateAt` (`SelectActiveKey` picks the eligible entry with the greatest `ActivateAt <= now`). There
   is therefore **always a signer**: a newly published key becoming visible never removes the incumbent,
   and activation only *swaps* the active slot at `ActivateAt` — it never leaves a gap where no key is
   eligible. No fail-closed hole is introduced by the publish-then-activate lead. (Fail-closed still
   applies only where it did in ADR 0011: `SelectActiveKey` returning `null` when *every* configured key
   has expired — a real misconfiguration, correctly surfaced, never signed around.)

Additional points (found while writing; carried through review):

4. **`PublicationLead` is durable, `ActivateAt`-derived on both tiers — Condition 1 fix.** Its
   enforcement is *only* `PublishAt = ActivateAt − PublicationLead` (§3), a durable derivation; all
   "since it first appeared in a listing" / observed-first-seen wording has been struck. This preserves
   ADR 0011 §3.5's ban on in-memory, restart-/replica-inconsistent observed-time bookkeeping — the
   invariant `PublicationLead >= RefreshInterval` is a config-level relationship, not per-key state. It
   is one concept with tier-specific *enforcement point* (advisory startup warning on Tier A where the
   operator owns `ActivateAt`; framework-derived `PublishAt` on Tier B), not the #409
   two-concepts-one-name mistake (Rejected Alternatives).

5. **`ISigner.Dispose` MUST release only its own per-activation handle — now a contract MUST (§2).** The
   base disposes the `ISigner` each time the active key changes; a remote `ISigner` (KV/KMS) referencing
   a shared, DI-owned SDK client MUST NOT tear that client down on `Dispose`.

6. **Tier A wall-clock expiry with no successor is a runtime fail-closed.** Since Tier A never re-reads,
   a set whose active key expires with no configured successor drifts to `SelectActiveKey == null` and
   signing fails closed at request time — the startup `HasTooSoonPendingActivation` warning covers
   too-soon *activation*, not eventual *expiry*. This is unchanged in kind from ADR 0011 and is correct
   fail-closed behaviour, noted for completeness.

Everything ADR 0011's security sign-off covered that this ADR does **not** change — the derived
`RetirementWindow` (§3.3 a/a′/b), JWKS-as-trust-boundary exposure (§4.3), the development-key
environment gate, minimum key strength, PEM file hardening, header/`kid`/`alg` consistency, `alg:none`
being unrepresentable — remains governed by ADR 0011 and its existing sign-off.

---

## Changelog

- **2026-07-20 — issue #418** — Initial ADR. Reverses #409's unified `RotatingKeySourceOptions`; splits
  signing providers into Tier A `KeySetOptions` (fixed set known up front — File/PFX/cert-store, and
  degenerate dev) and Tier B `KeySourceOptions` (re-read source — KV/DB/KMS/file-glob). Reshapes the
  provider contract from returning a live `SigningKeySet` of disposable key objects to `ListKeysAsync`
  (public `KeyListing` data) + `CreateSignerAsync` (lends an `ISigner` for the active key only);
  ships `LocalSigner`. Removes the reuse-guards, `HasKeySetChangedAsync`, `SigningKeyActivationDelay`,
  `AssumedJwksPropagationDelay`, `KeyRotationCheckInterval`, `StaticKeySourceOptions`, and the
  `Enabled` concept (kill-by-omission). Reuses `SigningKeyRotation` unchanged as the single engine;
  `RetirementWindow`/`PublishAt`/`DeactivateAt` all derived, operator sets only `ActivateAt`. Relaxes
  ADR 0011 §3.3(c) retired-private-key destruction to "bounded by request cadence" (the base requests
  non-active material only for the active key). **Supersedes ADR 0011 §3.2 (partial), §3.3(c), §3.4,
  §3.5.**
- **2026-07-21 — issue #418, security review on PR #419** — approve-with-conditions, adjudicated by
  @ChrisKlug; both must-fix conditions resolved and should-fix notes folded in. **Condition 1
  (Tier B `PublicationLead`):** removed the conflicting "since it first appeared in a listing"
  observed-time definition; `PublicationLead` is now durable, `ActivateAt`-derived only
  (`PublishAt = ActivateAt − PublicationLead`), preserving ADR 0011 §3.5's ban on in-memory
  observed-time bookkeeping (§1/§3). **Condition 2 (kill-by-omission):** omission disambiguated into
  three states — post-window vanish silent, within-window vanish dropped **plus `Warning`** (the
  vanished-`kid` detector, never downgraded), failed/partial read **MUST throw** (`ListKeysAsync`
  completeness contract) (§6). **Should-fix:** optional Tier A scavenge timer noted (§5);
  "non-active private material never materialised" corrected to a provider obligation for bundled
  formats (§2/§5); duplicate-`kid` rejection restated as running on derived thumbprints at
  `ListKeysAsync` time (§2/§7); `ISigner.Dispose`-must-not-dispose-shared-client raised to a contract
  MUST (§2).

---

## References

- **ADR 0011** — Signing Key Management (the design this ADR partially supersedes; still governs
  `RetirementWindow`, JWKS exposure, dev-key gate, key strength, `IJwtSigningService`, `JwkThumbprint`).
- **ADR 0012** — Signing-provider NuGet packaging model (why shared helpers are public in core).
- **ADR 0013 / 0014** — the authorization-code / refresh-token store "reshape what a third party
  implements down to a primitive" precedent this ADR follows for the signing provider.
- **Issue #418** — this design; **#409 / PR #413/#414** — the reversed unification; **#407 / PR #415** —
  the narrower fix whose review surfaced the problem (stays parked).
- RFC 7515 (JWS), RFC 7517 (JWK), RFC 7518 (JWA), RFC 7638 (JWK thumbprint), RFC 9700 (OAuth security BCP).
