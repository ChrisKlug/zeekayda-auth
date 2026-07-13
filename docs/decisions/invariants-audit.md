# Documentation-enforced invariants audit

> **Status:** Audit / inventory only. This document does **not** change any API. It surfaces the
> places where correctness currently depends on an implementer *reading* prose (XML docs, ADRs, or
> the how-to guides) rather than on the API shape making the wrong thing hard to express, so we can
> later redesign those APIs to make the invariant structural. It is deliberately not an ADR (it
> records no decision); it lives alongside `README.md` as a supporting document in this directory.

## Goal and framing

The design principle under test (Chris's framing):

> When subclassing or implementing an interface, the API should be designed such that it is
> EXTREMELY easy to do it right without really knowing that, and REALLY hard to do it wrong without
> reading all the docs, XML docs and ADRs.

An invariant is a *smell* for this audit when **all** of these hold:

1. It is expressed with modal/imperative prose ("MUST", "MUST NOT", "never throw", "atomic",
   "idempotent", "singleton-safe", "cheap", "fail closed", "use Ordinal") on a public interface,
   abstract class, virtual/protected member, or ADR/how-to aimed at extenders.
2. A conforming-*looking* implementation that violates it **compiles**, and usually **passes a
   naive single-threaded unit test**.
3. The violation's consequence is silent — a security bypass, a replay window, a credential leak,
   or a latent production-only failure — not a loud, immediate error.

Each finding below records: `file:line`, the invariant, who it binds, why the type system cannot
currently catch it, and a concrete structural fix. Fixes are tagged **breaking** / **non-breaking**
against the pre-1.0 public surface. Nothing here is implemented.

### What this codebase already does well (the patterns to replicate)

Several extension points have *already* migrated an invariant from prose to structure. These are
the templates the fixes below reach for:

- **Closed discriminated unions with a `private` constructor** — `AuthorizationCodeRedemptionOutcome`
  and `RefreshTokenConsumptionOutcome` make "handle every case" a compiler concern and make
  external subclassing impossible. Exhaustiveness is structural.
- **A runtime guard that fails *at the boundary*, loudly** — `JwtSigningService` no longer merely
  documents "`LoadKeysAsync` must return a new instance"; it reference-compares the returned set and
  throws `InvalidOperationException` immediately (`JwtSigningService.cs:266`), instead of letting the
  mistake surface later as a disconnected `ObjectDisposedException`.
- **A base class that absorbs the cross-cutting requirement** — `ClientSecretHasher<TSecret>`
  swallows exceptions from `VerifyCore` (`ClientSecretHasher.cs:42-49`) so the "never throw from
  Verify" rule is enforced for the subclass rather than trusted.
- **Fail-fast startup validators** — `ISanitizingLogger<>` says "do not implement this directly",
  and `SanitizingLoggerRegistrationStartupValidator` actually fails startup if a host shadows the
  registration. The prose is backed by a runtime gate.
- **A shipped analyzer** — `ZEEKAYDA0001/0002/0003` already exist, so "add an analyzer diagnostic"
  is a *realistic, precedented* fix in this repo, not a wish.

The findings are the invariants that have **not** yet been given one of these treatments.

---

## 1. Refresh-token and authorization-code stores

`IAuthorizationCodeStore` and `IRefreshTokenStore` are the highest-density concentration of
doc-enforced, security-critical invariants in the codebase. They are pure interfaces: the framework
hands a custom store raw material and trusts it to do the right thing, with no base class in the
path.

### 1.1 Atomicity of check-and-consume (highest severity)

- **Where:** `src/ZeeKayDa.Auth/Stores/IAuthorizationCodeStore.cs:120-128` (`TryRedeemAsync`);
  `src/ZeeKayDa.Auth/Stores/IRefreshTokenStore.cs:88-101` (`TryConsumeAsync`).
- **Invariant:** the check-and-consume MUST be atomic (CAS / Lua / transaction). Two concurrent
  requests for the same handle MUST yield exactly one `Consumed`/`Redeemed` and one
  `AlreadyConsumed`/`AlreadyRedeemed`.
- **Binds:** every custom store author.
- **Why unenforceable today:** the interface returns a value describing the outcome, but *how* the
  outcome was computed is invisible to the type system. A naive `var e = await Get(); if (e.Consumed)
  ... ; await MarkConsumed();` compiles, passes every single-threaded test, and only fails under a
  concurrent replay — which is precisely the attack (RFC 9700 §2.1 reuse detection) the interface
  exists to defend against. This is the worst kind of smell: silent, security-critical, and
  invisible until production load.
- **Proposed structural fix (revised — tier-1 reshape first):** shrink the atomic obligation. Today
  the store implements the *entire* outcome state machine atomically. Reduce it to **one narrow atomic
  primitive** — `TryMarkConsumedAsync(key) -> bool` (refresh tokens) / an atomic redeem-and-stamp
  primitive (codes) — and have the **framework** compose the full outcome from that primitive plus the
  read-only `FindAsync`: null → `NotFound`; client ≠ presenter → `ClientMismatch`; family revoked →
  `Revoked`; primitive `true` → `Consumed`, `false` → `AlreadyConsumed` (reuse). The only thing that
  must be atomic is a single-row conditional flip (`UPDATE … WHERE consumed = 0`, `SETNX`/Lua,
  DynamoDB conditional write), correct by inspection. This moves the invariant-bearing composition into
  the framework (tier-1). **Breaking** — coordinate with §1.2's `StoreKey` (the primitive takes the
  `StoreKey`). Tracked in #353.
- **Residual, cannot be made fully structural:** the CLR cannot prove the primitive itself is atomic.
  A conformance **test kit** (high-concurrency hammer against the one primitive) is the honest tier-3
  backstop, alongside first-party `RedisRefreshTokenStore` / EF stores so most authors never hand-roll
  even the primitive.

### 1.2 The store must hash the raw handle before using it as a key

- **Where:** `IAuthorizationCodeStore.cs:47-51` ("MUST NOT persist this value directly; it MUST
  derive the storage key as `Base64Url(SHA-256(code))`"); `IRefreshTokenStore.cs:44-48`
  ("expected to hash this before using it as a storage key").
- **Invariant:** the store must not persist the cleartext handle; it must key on a hash.
- **Binds:** every custom store author.
- **Why unenforceable today:** the framework passes a raw `string code` / `string tokenHandle` and
  trusts the store to hash it. `_db.Insert(code, entry)` compiles and works perfectly — the
  weakness (a store-database compromise leaks directly usable handles) is invisible in normal
  operation.
- **Proposed structural fix:** move the hashing to the framework and pass an opaque pre-hashed key
  type — e.g. a `readonly struct StoreKey` whose only constructor is internal and whose value is
  already `Base64Url(SHA-256(handle))`. The store receives `StoreAsync(StoreKey key, …)` and
  *cannot* obtain the cleartext handle to persist by mistake. This removes the responsibility from
  the extender entirely (the "pit of success" ideal). **Breaking** (signature change on both store
  interfaces) — flag as a pre-1.0 window change; the value is high because it makes the insecure
  option unrepresentable.

### 1.3 Fail-closed on infrastructure error

- **Where:** `IAuthorizationCodeStore.cs:36-39, 59-67, 130-133`; `IRefreshTokenStore.cs:32-37,
  96-101` ("MUST throw `ZeeKayDaStoreException`… MUST NOT convert to `NotFound`").
- **Invariant:** an I/O failure must surface as `ZeeKayDaStoreException`, never be swallowed into a
  `NotFound`/`NotFound`-shaped success — otherwise reuse detection is silently suppressed.
- **Binds:** every custom store author.
- **Why unenforceable today:** `catch { return NotFound; }` compiles. `NotFound` is a legal return
  value, so the type system sees a valid outcome, not a swallowed outage.
- **Proposed structural fix:** conformance-kit test only — and this is the honest ceiling, confirmed
  on re-review. **Tier-1 is impossible:** `NotFound`/a null lookup must stay a legitimate value (an
  unknown handle is a real outcome), so no type can distinguish a genuine not-found from one fabricated
  in a `catch`. Even the §1.1 primitive reshape does not help — the store's `FindAsync`/primitive can
  still `catch { return null/false; }`, both semantically valid. **Tier-2 is impossible:** a swallowed
  exception produces a well-formed value, so the framework has no boundary at which to detect the
  hidden outage; a re-throwing wrapper would need the very information the swallow destroyed. A
  fault-injecting kit test (against the reshaped primitive) is the realistic lever. **Non-breaking.**
  Tracked in #358.

### 1.4 `RevokeFamilyAsync` must be idempotent

- **Where:** `IRefreshTokenStore.cs:116-127` ("This operation MUST be idempotent… MUST NOT throw"
  on an already-revoked or unknown family).
- **Invariant:** revoking twice, or revoking an unknown family, is a successful no-op.
- **Binds:** custom store authors. Matters because the token endpoint calls it defensively from
  catch blocks and on the empty-`FamilyId` DP-rotation edge case
  (`AuthorizationCodeRedemptionOutcome.cs:103-121`).
- **Why unenforceable today:** a store that throws on unknown-family compiles and passes the happy
  path; the throw only manifests on the defensive/edge call.
- **Proposed structural fix:** conformance-kit test asserting double-revoke and unknown-family are
  no-ops. **Non-breaking.** Confirmed honest ceiling: **tier-1** is unavailable (a correct backend op
  is already idempotent — `UPDATE … SET revoked=1 WHERE family=@f` no-ops on zero rows — but the CLR
  cannot force an arbitrary backend to express it that way without removing its ability to report
  genuine transport failures per §1.3); **tier-2 is counterproductive** (a framework catch to fake
  idempotency would also swallow the `ZeeKayDaStoreException` §1.3 requires — the two cannot be
  distinguished). Tracked in #359.

### 1.5 In-memory-only / single-instance and multi-tenant namespacing

- **Where:** `IRefreshTokenStore.cs:8-31`; `IAuthorizationCodeStore.cs:28-33`.
- **Invariant:** the default in-memory store silently disables reuse detection across instances;
  multi-tenant isolation is the custom store's job (namespace keys by tenant).
- **Binds:** operators choosing the default store at scale, and multi-tenant store authors.
- **Why unenforceable today:** the interface carries no tenant parameter and no instance-count
  awareness, by design. Nothing in the shape signals "this is unsafe with N>1 instances".
- **Proposed structural fix (revised):** the "make it visible" goal is **already met at a stronger
  tier than a warning**. `InMemoryStoreWarningService.StartAsync` already *fails startup* (throws
  `ZeeKayDaConfigurationException`) when an in-memory store runs outside Development without an explicit
  `allowOutsideDevelopment: true` opt-in — a tier-2 fail-closed gate, not a tier-3 log. The tenancy
  limitation itself is an accepted architectural boundary, not a defect. The only residual is a
  **messaging gap**: the existing failure/override text names cross-instance reuse detection but not
  the multi-tenant isolation risk; extend the message constants to name it. **Non-breaking.** Tracked
  in #360.

---

## 2. Signing-key providers (`JwtSigningService<TOptions>`)

This base class is largely a **success story**: the "new instance every load" invariant is now
runtime-enforced (`JwtSigningService.cs:266-273`), key/alg compatibility and duplicate-`kid` are
validated (`:401-421`), and disposal ownership is handled by the base via refcounting. The residual
findings are narrower.

### 2.1 "The first entry is the active signing key" is positional, not named

- **Where:** `JwtSigningService.cs:57-59` and `SigningKeySet.cs:30-31, 60-89`
  (`ActiveKey => Keys[0]`, "first pair is the active signing key").
- **Invariant:** a provider's `LoadKeysAsync` must return the active key at index 0; retired keys
  follow.
- **Binds:** every custom signing provider author.
- **Why unenforceable today:** the active key is identified by *position* in an
  `IReadOnlyList<SigningKeyPair>`. A provider that builds the list in, say, creation-date order and
  puts the newest (active) key last will sign every token with a retired key — it compiles, and JWKS
  still publishes all keys, so tokens even verify. The failure is subtle (wrong `kid`, rotation
  semantics broken), not a crash.
- **Proposed structural fix:** change `SigningKeySet`'s construction to name the active key
  explicitly — e.g. `new SigningKeySet(active: pair, retired: [...])` or a factory
  `SigningKeySet.Create(SigningKeyPair active, IEnumerable<SigningKeyPair> retired)`. The active key
  becomes impossible to leave ambiguous. **Breaking** (constructor signature) but small blast radius
  (only the four first-party providers plus any custom provider) and squarely in the pre-1.0 window.

### 2.2 `HasKeySetChangedAsync` override must be fail-closed and cheap

- **Where:** `JwtSigningService.cs:89-120` (override must be metadata-only/cheap; throwing is
  fail-closed by design; "do not invent divergent fail-soft behaviour").
- **Invariant:** an override must (a) be a cheap metadata check, and (b) not swallow-and-continue on
  error.
- **Binds:** providers that override the hook (e.g. the Key Vault cached provider, #334).
- **Why unenforceable today:** (a) "cheap" is unmeasurable by the type system — an override that
  downloads full key material compiles and merely defeats the optimisation. (b) The fail-closed
  requirement is *partly* structural already: the base class does not catch, so a thrown exception
  propagates. The residual smell is a provider that internally `try/catch`es and returns `true`/
  `false` to fake "unchanged" — that swallow compiles.
- **Proposed structural fix:** low-priority. The fail-closed half is already the path of least
  resistance (do nothing → exceptions propagate). For the "cheap" half there is no realistic
  structural fix; leave as documented guidance backed by ADR 0011 §3.2. **No change recommended**
  beyond noting it — the base class shape already nudges correctly.

### 2.3 `SignInputAsync` override: `SigningKeyPair.PrivateKey` is "intentionally unused" by remote overrides

- **Where:** `JwtSigningService.cs:173-181`; `SigningKeyPair` at `SigningKeySet.cs:8-15`.
- **Invariant:** remote-signing overrides ignore `activeKey.PrivateKey` (it holds no usable private
  material for a KMS/HSM path); the descriptor selects the remote key.
- **Binds:** remote-signing provider authors.
- **Why partly-enforceable:** this is a *documented-unused member*, not a violable invariant — the
  worst outcome is a confused reader, not a security bug. The remote reader already returns a
  public-only key object (`IKeyVaultCertificateReader.cs:41-63`), so there is no private material to
  misuse.
- **Proposed structural fix:** optional. A `SignInputContext` parameter object that omits
  `PrivateKey` for the remote path would remove the dead member, but the header notes the
  allocation/indirection cost isn't worth it. **No change recommended**; listed for completeness.

### 2.4 The reference-equality guard only catches instance reuse, not underlying-key reuse

- **Where:** `JwtSigningService.cs:60-79` (`LoadKeysAsync` remarks, explicitly: "this is a
  reference-equality tripwire, not a deep check"); the guard itself at `:266-274`.
- **Invariant:** `LoadKeysAsync` must return a set built from genuinely new private-key objects,
  not merely a new `SigningKeySet` wrapper around the *same* `AsymmetricAlgorithm` instances the
  previous set held.
- **Binds:** every custom signing provider author — especially one with an internal key cache that
  might be tempted to construct `new SigningKeySet(keys)` from cached `SigningKeyPair`s instead of
  overriding `HasKeySetChangedAsync` to report "unchanged."
- **Why unenforceable today:** the guard at `:266-274` compares the returned `SigningKeySet`
  *instance* against the previously cached one by reference. It does not (and today cannot)
  inspect whether the `PrivateKey` objects inside the new set are the same objects as before. A
  provider passing through the same `AsymmetricAlgorithm` references inside a fresh `SigningKeySet`
  wrapper compiles, satisfies the outer tripwire (it *is* a different instance), and only surfaces
  as the exact disconnected `ObjectDisposedException` the guard exists to prevent — just delayed
  one refresh cycle, once the base class disposes what it thinks is the superseded set.
- **Proposed structural fix:** extend the existing guard to also compare, per shared `kid`, each new
  key pair's `PrivateKey` reference against the corresponding object in the previous set, and throw
  the same `InvalidOperationException` on any collision. This is additive to the check that already
  exists at the same call site — no public signature changes. **Non-breaking.** Confirmed as the right
  level (tier-2, loud+immediate): a tier-1 reshape (refcount by underlying `AsymmetricAlgorithm`
  identity instead of by `SigningKeySet` instance, so reused key objects are never double-disposed)
  was considered but rejected as a disproportionate rework of the disposal model for a mistake the
  extended guard already catches immediately. Tracked in #361.

---

## 3. Client-secret hashers (`ClientSecretHasher<TSecret>`, `IClientSecretHasher`)

The base class already absorbs exception-swallowing and null/whitespace rejection (good). Two
invariants remain prose-only.

### 3.1 `VerifyCore` must use fixed-time comparison

- **Where:** `ClientSecretHasher.cs:19-22, 65-69`; `IClientSecretHasher.cs:6-12`.
- **Invariant:** all hash comparisons in `VerifyCore` must use
  `CryptographicOperations.FixedTimeEquals`.
- **Binds:** every custom hasher author.
- **Why unenforceable today:** `stored.Hash == presentedHash` (or `SequenceEqual`) compiles, passes
  every functional test (it returns the correct boolean!), and silently introduces a timing oracle.
  Correctness and security diverge: the *wrong* code is *functionally* right.
- **Proposed structural fix (revised — tier-1 reshape first):** `VerifyCore` returns a raw `bool`, so
  the subclass owns the whole comparison. Reshape it so the subclass only *computes hash bytes*
  (`ComputeHash(stored, presented)` + `GetStoredHash(stored)`) and the **base class** performs
  `CryptographicOperations.FixedTimeEquals` itself, once, centrally — the subclass can no longer get
  the comparison wrong because it never performs one. PBKDF2 fits cleanly (it already computes
  `expected` then calls `FixedTimeEquals`). **Design tension:** library-owns-verify schemes
  (bcrypt/scrypt) expose a single constant-time `Verify` and don't fit "return raw bytes"; the ADR
  must decide how to accommodate them (e.g. a clearly-exceptional `VerifyOpaque` escape hatch), which
  is why this is now a `type:design` public-API reshape. The analyzer (`ZEEKAYDA0004`, Warning) is
  retained only as the tier-3 backstop for that escape-hatch path, not the primary fix. Coordinate
  with §3.2 (same base class). Tracked in #362.

### 3.2 The memory-safety guarantee silently degrades if only `CreateCore(string)` is overridden

- **Where:** `ClientSecretHasher.cs:23-28, 76-82`; `IClientSecretHasher.cs:55-60`
  (span override optional; "Custom hashers that only override `CreateCore(string)` will still
  allocate an intermediate managed string via the base-class fallback, defeating the zeroing
  benefit"). The how-to spends a whole warning box on this
  (`implement-custom-extension-points.md:211-230`).
- **Invariant:** to preserve the `Create(ReadOnlySpan<char>)` memory-safety promise, a hasher should
  override `CreateCore(ReadOnlySpan<char>)`, not just `CreateCore(string)`.
- **Binds:** custom hasher authors.
- **Why unenforceable today:** `CreateCore(ReadOnlySpan<char>)` is `virtual` with a
  string-allocating fallback (`:81-82`), while `CreateCore(string)` is `abstract`. So the compiler
  *forces* the author to implement the allocating one and makes the safe one optional — the
  incentives are exactly backwards from the "pit of success" goal. The caller dutifully zeros their
  buffer, but a full managed-string copy of the secret lingers on the heap.
- **Proposed structural fix (revised — flip is the primary direction):**
  - **(b) Flip the abstract member (tier-1, preferred):** make `CreateCore(ReadOnlySpan<char>)`
    abstract and `CreateCore(string)` the virtual convenience shim. Then the safe override is the
    mandatory one — the unsafe path is something you must go out of your way to reintroduce. The
    "string-only crypto lib" objection is **not a blocker**: such a hasher writes a one-line,
    consciously-owned `CreateCore(span) => Hash(span.ToString())` shim, making the allocation explicit
    rather than silently injected behind an author who thought they were safe. **Breaking**; viable in
    the pre-1.0 window. Coordinate with §3.1 (same base class, one combined reshape).
  - **(a) Analyzer** (`ZEEKAYDA0005`, Warning): retained only as an interim stopgap if the flip must
    be deferred — it nags about the incentive rather than fixing it, so it is not the endpoint.
    Tracked in #357.

---

## 4. Client authenticators (`IClientAuthenticator`)

### 4.1 `CanHandle` must be a cheap shape check

- **Where:** `IClientAuthenticator.cs:33-35`; how-to §6 warning
  (`implement-custom-extension-points.md:379-384, 422-445, 489`).
- **Invariant:** `CanHandle` must do no crypto, DB, or I/O — it runs for every authenticator on
  every token request.
- **Binds:** custom authenticator authors.
- **Why unenforceable today:** `CanHandle` is a synchronous `bool`. An author who does I/O must
  block (`.Result`) inside it — which compiles and works, just slowly and with thread-pool risk. The
  cost is latency across *all* clients, invisible until load.
- **Proposed structural fix:** the *synchronous* `bool CanHandle(...)` signature is itself the tier-1
  nudge — there is no `Task` to await, so doing I/O requires actively reaching for `.Result`. "Cheap"
  in general is unmeasurable (the CLR cannot bound an arbitrary body's cost) and there is no loud
  tier-2 boundary for "too expensive." The catchable residual is the blocking-async antipattern, which
  an analyzer flags (`.Result`, `.GetAwaiter().GetResult()`, `.Wait()`) — tier-3, the honest ceiling
  for this invariant. **Non-breaking.** Tracked in #371.

### 4.2 Custom authenticators must not declare or return `"none"`

- **Where:** `IClientAuthenticator.cs:12-16` ("MUST NOT declare or return … `None` … reserved for the
  `CompositeClientAuthenticator` fallback").
- **Invariant:** `AuthenticationMethods` / `CanHandle` must never surface `"none"`.
- **Binds:** custom authenticator authors.
- **Why unenforceable today:** `AuthenticationMethods` is `IReadOnlySet<string>`; `"none"` is a
  legal string. Nothing rejects it.
- **Proposed structural fix (revised — largely already in place):** on re-review this is already
  enforced at two tiers, not just proposed. (1) `AuthenticatorCoverageValidator.Validate`
  (`AuthenticatorCoverageValidator.cs:80-87`) *already* fails startup if any authenticator declares
  `"none"` (also rejecting whitespace/casing variants). (2) The runtime bypass is *already
  structurally impossible*: the `"none"` fallback (`AuthenticateNone`) is reached only when no
  authenticator's `CanHandle` fired and is owned entirely by the composite; a custom authenticator
  returning `"none"` is rejected first by the "returned method must be in the declared set" check
  (`CompositeClientAuthenticator.cs:114`) — and declared `"none"` is a startup failure — so it can
  never inject itself into the fallback. Residual work is a **regression test** locking in both, not a
  new validator. **Non-breaking.** Tracked in #363.

### 4.3 `AuthenticateAsync` must return `NotValid()`, not throw; must be timing-safe

- **Where:** `IClientAuthenticator.cs` security-contract table in how-to §6
  (`implement-custom-extension-points.md:485-493`): "Return `ClientAuthenticationResult.NotValid()`
  on failure — never throw" (throwing yields a 500 not a 401); delegate all comparison to the hasher.
- **Invariant:** failures return a result; no throw; no direct string comparison.
- **Binds:** custom authenticator authors.
- **Why unenforceable today:** unlike `ClientSecretHasher.Verify` (which the base class wraps in
  `try/catch`, `ClientSecretHasher.cs:42-49`), the composite deliberately does **not** catch around
  `AuthenticateAsync` — so a throw escapes as a 500. The "never throw" rule is therefore pure prose
  with a worse failure mode than the analogous hasher path.
- **Proposed structural fix:** have `CompositeClientAuthenticator` wrap each `AuthenticateAsync` call
  and convert an unexpected exception into a logged `NotValid()` (fail-closed), mirroring the hasher
  base class. This makes "throwing is harmless" true by construction. **Non-breaking** (behavioural;
  turns a 500 into a 401, which is the documented desired outcome anyway). The timing-safe half is
  covered by routing comparisons through `IClientSecretHasher` and by finding §3.1's analyzer.

---

## 5. Client repository & registration (`IClientRepository`, `IClientRegistration`, `IClientRegistrationValidator`)

### 5.1 Custom repositories must call the validator before persisting

- **Where:** `IClientRepository.cs:14-21`; `IClientRegistrationValidator.cs:12-16`; ADR 0007 §6.1;
  how-to `:345-349`. Already backed by analyzer **ZEEKAYDA0003**.
- **Invariant:** a custom repo must resolve `IClientRegistrationValidator` and call `Validate`
  before writing a registration.
- **Binds:** custom repository authors.
- **Why unenforceable today — and why this is the archetypal case:** the framework owns only the
  *read* path (`FindByClientIdAsync`). The write path lives entirely in the consumer's code, which
  the framework never sees, so it *cannot* interpose. ZEEKAYDA0003 exists but its own reference doc
  admits it is "a presence check, not a correctness check… does not verify that the validator is
  ever invoked" (`analyzer-rules.md:239-248`). So even the mitigation is documentation-enforced at
  its core.
- **Proposed structural fix (revised — validate at the read boundary the framework owns):** the
  original "framework doesn't own writes, so it can't interpose" concedes too early. The framework
  *does* own the read boundary — every registration crosses `FindByClientIdAsync` before any security
  decision — so running `IClientRegistrationValidator.Validate` there (once, cached per `client_id`,
  fail-closed) makes enforcement **universal for every custom repository**, not just write-path
  adopters. This reuses the same framework-owned decorator seam as §5.3's ordinal normalization
  (design one seam, not two). The write-side abstraction (`IClientRegistrationWriter` /
  `ValidatingClientStore`) is still worth offering as an *ergonomic paved path* (fail-at-write error
  surface) layered on top, and ZEEKAYDA0003 stays as a nudge — but neither is load-bearing once
  read-boundary validation is structural. **Design tension:** cost (validate-once-and-cache is
  essential) and fail-closed semantics (an invalid registration surfacing as "not found" must not
  silently mask a real misconfig). **Non-breaking** (internal decorator). Tracked in #356.

### 5.2 `FindByClientIdAsync` must return `null`, never throw, for unknown/malformed ids

- **Where:** `IClientRepository.cs:9-13, 29-33` (throwing "changes timing and undermines enumeration
  defence").
- **Invariant:** unknown/malformed `client_id` → `null`, not an exception.
- **Binds:** custom repository authors.
- **Why unenforceable today:** a `throw new KeyNotFoundException()` compiles. The timing difference
  that enables client enumeration is invisible to any functional test.
- **Proposed structural fix:** conformance test — the honest ceiling. **Tier-1 is impossible** (no
  type encodes "never throws"; a non-nullable result would outlaw the legitimate not-found path).
  **Tier-2 (a catch-and-map decorator) is explicitly rejected** as it collides with §1.3: catching to
  return `null` would convert a store *outage* into a silent "client not found", suppressing the
  fail-closed signal, and the framework cannot distinguish "threw because unknown" from "threw because
  down." So fold into §5.1's read-boundary paved-path story with an explicit "unknown id returns null"
  test rather than a blanket catch. **Non-breaking.** Tracked in #365.

### 5.3 String-set members must be compared with `Ordinal`; the set's own comparer is untrusted

- **Where:** `IClientRegistration.cs:17-24` ("This is a security contract, not a suggestion") plus
  per-member repeats at `:64-68, 74-77, 83-86, 101-105` (`RedirectUris`, `PostLogoutRedirectUris`,
  `AllowedScopes`, `AllowedTokenEndpointAuthMethods`).
- **Invariant:** every consumer of these `IReadOnlySet<string>` members must re-check membership with
  `StringComparer.Ordinal` and must not trust the set's built-in comparer — because a custom repo
  may hand back a set built with `OrdinalIgnoreCase` (or a culture comparer), turning redirect-URI
  matching into a bypass (RFC 9700 §2.1 exact-match requirement).
- **Binds:** *every internal consumer* of a registration, forever — this is the most fragile finding
  because it binds first-party code on every future call site, not just external extenders. One
  forgotten `.Contains(uri)` that trusts the set comparer is an open-redirect / URI-confusion bug.
- **Why unenforceable today:** `IReadOnlySet<string>` carries an *arbitrary* comparer, and
  `set.Contains(x)` uses it. The type cannot express "the comparer must be ordinal".
- **Proposed structural fix (strongest recommendation in this audit):** normalise at the trust
  boundary. When a registration enters the framework from `IClientRepository`, run it through an
  internal wrapper that copies each string set into a `FrozenSet<string>(StringComparer.Ordinal)`
  (in-memory clients already get this; custom-repo results currently do **not**). Then every
  downstream `.Contains` is ordinal by construction and the per-call-site rule evaporates.
  **Critical caveat found on re-review:** this is only tier-1 if the decorator is applied
  *automatically and unavoidably* by the framework to whatever `IClientRepository` the consumer
  registers. If the author has to know to register it, it is tier-3 in a tier-1 costume. Making it
  unavoidable is a non-trivial DI-seam decision (MS.DI has no built-in decoration; internal consumers
  inject `IClientRepository` directly, e.g. `CompositeClientAuthenticator.cs:22`) — so this is now a
  `type:design` item, co-designed with §5.1 so there is one framework-owned normalize-and-validate
  seam. **Non-breaking** (internal decorator); the later `OrdinalStringSet` member-type change is a
  separate breaking follow-up. Tracked in #366.

### 5.4 `AllowedSigningAlgorithms` subset constraint must be enforced at write time by custom repos

- **Where:** `IClientRegistration.cs:140-145` ("validated at startup for in-memory clients; custom
  repositories MUST enforce the subset constraint at write time").
- **Invariant:** when non-null, must be non-empty and a subset of
  `IdTokenOptions.SigningAlgValuesSupported`.
- **Binds:** custom repository authors.
- **Why unenforceable today:** same read/write split as §5.1 — the constraint is checked on the
  in-memory registration path but a custom repo's write path is unseen.
- **Proposed structural fix:** folds into §5.1's **read-boundary** `Validate` story (the validator
  already owns this rule for the in-memory path) — so the subset constraint is enforced universally
  for every custom repository, not merely write-path adopters. **Non-breaking.** Tracked in #367.

---

## 6. Cross-cutting: `ISanitizingLogger<T>` (already structural — recorded as the model)

- **Where:** `src/ZeeKayDa.Auth/Logging/ISanitizingLogger.cs` ("Do not implement this interface
  directly").
- **Status:** **already enforced.** `SanitizingLoggerRegistrationStartupValidator` fails fast if a
  host shadows the registration, and `ZEEKAYDA0001` forbids injecting raw `ILogger<T>`. Prose is
  backed by both a startup gate and an analyzer.
- **Residual micro-gap:** the startup validator lives in `ZeeKayDa.Auth.AspNetCore`; a core-only host
  that never runs the AspNetCore startup validators would not get the fail-fast. Low priority — the
  supported hosting path is AspNetCore. Noted for completeness; **no change recommended.**

---

## 7. Async / cancellation contract on `IScopeRepository` and `IDiscoveryDocumentProvider`

- **Where:** interface XML docs are clean, but the how-to imposes real invariants:
  `implement-custom-extension-points.md:119-152` — honour the token, never sync-over-async, never
  swallow `OperationCanceledException`.
- **Invariant:** implementations must propagate the `CancellationToken`, must not block a thread with
  `.Result`/`.GetAwaiter().GetResult()`, and must let `OperationCanceledException` propagate.
- **Binds:** scope/discovery/repository authors (any `ValueTask`-returning extension point).
- **Why unenforceable today:** `ValueTask.FromResult(BlockingCall().Result)` compiles. The
  thread-pool-starvation consequence only appears under load.
- **Proposed structural fix:** the `ValueTask`/`Task` return + `CancellationToken` parameter are
  already the tier-1 nudge (the async signature exists to be awaited, the token to be honoured). But
  "pass the token through", "let `OperationCanceledException` propagate", and "don't sync-over-async"
  are body properties no signature can force, and there is no loud tier-2 boundary for a blocked
  thread. The one mechanically-detectable case is the blocking-async antipattern — an analyzer flags
  it (overlaps with §4.1; could be one rule). Cancellation propagation / non-swallowing remain honest
  documented-only guidance. Tier-3, honest ceiling. **Non-breaking.** Tracked in #372.

---

## Summary table

| # | Extension point | Invariant (abridged) | Current enforcement | Proposed structural fix | Breaking? |
|---|---|---|---|---|---|
| 1.1 | Code / refresh-token stores | Check-and-consume must be **atomic** | Docs only | **Tier-1: shrink to one atomic primitive (`TryMarkConsumedAsync`), framework composes outcome**; kit as backstop | **Yes** |
| 1.2 | Code / refresh-token stores | Must **hash the raw handle** before keying | Docs only | Pass pre-hashed `StoreKey`; framework does the hashing | **Yes** |
| 1.3 | Code / refresh-token stores | **Fail closed**: I/O error → `ZeeKayDaStoreException`, never `NotFound` | Docs only | Fault-injection kit test (tier-1/2 impossible: NotFound must stay legit; swallow leaves no boundary) | No |
| 1.4 | Refresh-token store | `RevokeFamilyAsync` must be **idempotent** | Docs only | Conformance-kit double-revoke / unknown-family test (tier-2 catch would break §1.3) | No |
| 1.5 | Refresh-token / code store | In-memory single-instance & tenant namespacing | **Already fail-closed at startup** | Complete the message (name tenant-isolation risk); guard already stronger than a warning | No |
| 2.1 | Signing providers | **Active key = index 0** (positional) | Docs only | Name the active key explicitly in `SigningKeySet` construction | **Yes** |
| 2.2 | Signing providers | `HasKeySetChangedAsync` cheap & fail-closed | Docs + base-class shape (fail-closed already nudged) | None beyond noting; shape already correct | No |
| 2.3 | Signing providers | `PrivateKey` unused by remote override | Docs (harmless) | None recommended | No |
| 2.4 | Signing providers | New `SigningKeySet` must not wrap the **same underlying private-key objects** as before | Docs only (guard is reference-equality on the wrapper, not the keys) | Extend existing guard to compare `PrivateKey` references per shared `kid` | No |
| 3.1 | Client-secret hashers | `VerifyCore` must use **fixed-time compare** | Docs only | **Tier-1: subclass computes bytes, base owns `FixedTimeEquals`** (`type:design`); `ZEEKAYDA0004` only backstops the escape hatch | **Yes** |
| 3.2 | Client-secret hashers | Override the **span** `CreateCore` for memory safety | Docs; incentives backwards (span is optional) | **Tier-1: flip — make span overload abstract** (analyzer only an interim stopgap) | **Yes** |
| 4.1 | Client authenticators | `CanHandle` must be **cheap** (no I/O) | Docs + sync signature (already nudges) | Analyzer flagging sync-over-async in `CanHandle` (honest ceiling) | No |
| 4.2 | Client authenticators | Must not surface `"none"` | **Startup validator already rejects declared; dispatch already blocks runtime** | Regression test locking in existing tier-1/tier-3 guards | No |
| 4.3 | Client authenticators | `AuthenticateAsync` must not throw | Docs only (worse: throw → 500) | Composite wraps call, maps exception → `NotValid()` (tier-1: framework owns it) | No |
| 5.1 | Client repository | Must **validate before persist** | Docs + `ZEEKAYDA0003` (presence check only) | **Tier-1: validate at framework-owned read boundary (universal)**; write abstraction as paved path | No |
| 5.2 | Client repository | `FindByClientIdAsync` returns `null`, never throws | Docs only | Conformance test (tier-2 catch conflicts with §1.3) | No |
| 5.3 | Client registration | String sets compared **Ordinal**; set comparer untrusted | Docs ("security contract") | **Normalise to `FrozenSet(Ordinal)` — but only tier-1 if applied automatically** (`type:design`, DI seam) | No (decorator) / **Yes** (member type) |
| 5.4 | Client registration | `AllowedSigningAlgorithms` subset at write time | Docs only | Folds into 5.1 read-boundary validation (universal) | No |
| 6 | `ISanitizingLogger<T>` | Do not implement directly | **Startup validator + `ZEEKAYDA0001`** (enforced) | Minor: extend to core-only hosts | No |
| 7 | Scope / discovery providers | Honour cancellation; no sync-over-async | Docs (how-to) only | Analyzer for sync-over-async (shared with 4.1) | No |

### Highest-leverage items (revised after the tier-framework re-review)

1. **§1.1 store atomicity** — the most dangerous silent invariant (replay-detection bypass under
   concurrency). The strongest fix is now the **tier-1 primitive reshape** (shrink the store's atomic
   obligation to a single conditional flag-flip; the framework composes the outcome), breaking but
   pre-1.0. The conformance kit drops to a tier-3 backstop hammering the one primitive.
2. **§5.3 ordinal set comparison** and **§5.1 read-boundary validation** — both hinge on one
   framework-owned normalise-and-validate seam over `IClientRepository`. This is only structural if the
   seam is applied *automatically and unavoidably*, which is a DI-seam design decision (both now
   `type:design`). Get the seam right once and §5.1/§5.3/§5.4 all become universal, not adopter-only.
3. **§1.2 hash-the-handle**, **§2.1 active-key-by-position**, **§3.1 base-owns-`FixedTimeEquals`**, and
   **§3.2 flip-the-abstract-overload** — the cleanest "make the wrong thing unrepresentable" wins, all
   breaking but squarely in the pre-1.0 window. §3.1 and §3.2 reshape the same `ClientSecretHasher<T>`
   surface and should be one coordinated break.

### Re-review note (tier framework, Design Principle #6)

Every finding was re-checked against the three-tier ranking. Where the original audit reached for a
test-kit / analyzer / startup-validator (tier-3), a tier-1 reshape or tier-2 guard was sought first;
several were found and are now the primary direction (§1.1, §3.1, §5.1, §5.3). Where tier-3 remains the
honest ceiling (§1.3, §1.4, §5.2, §4.1, §7), the reason a structural fix is genuinely impossible is now
stated explicitly rather than assumed. Two findings turned out to be **already enforced more strongly
than proposed**: §1.5 (in-memory stores already fail startup outside Development, not merely warn) and
§4.2 (the `"none"` declaration already fails startup and the runtime bypass is already structurally
impossible via the composite dispatch). Clusters for follow-up ADRs: a **store reshape + conformance
kit** ADR (§1.1/1.3/1.4, with §1.2 `StoreKey`), a **`ClientSecretHasher` protected-surface reshape**
ADR (§3.1/§3.2), and a **client-registration trust-boundary** ADR (one seam for §5.1/§5.3/§5.4).
