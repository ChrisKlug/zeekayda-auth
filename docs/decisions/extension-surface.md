# Extension surface

What a third party may implement, what they may only consume, and the mechanics that keep the two
apart. Each seam's own rules live in its topic file; this is the shape they share.

## Decisions in force

**The house pattern: a public seam paired with a closed collection or member.** Where a subsystem has
both a protocol to enforce and a genuinely variable part, the variable part gets a public interface
and the protocol gets a type a third party structurally cannot join. It shows up three times, arrived
at independently:

- **Gate versus verifier.** `IStartupVerifier` is public and third parties register into it; the gate
  collection ahead of it is `internal`, so no verifier can claim the position ahead of the
  sanitizing-logger check (`startup-verification.md`).
- **Coordinator versus backing store.** The store coordinators are `public` so the ASP.NET Core
  package can inject them, but each carries an `internal` member only a friend assembly can satisfy.
  Publicly consumable, not third-party implementable — the asymmetry actually needed
  (`token-stores.md`).
- **The framework-internal store key.** A backing store receives keys as an opaque struct whose
  constructor is internal, so "hash the handle before you key anything on it" is unrepresentable in
  third-party code rather than documented.

Reach for this before reaching for a doc comment. It is what the register means by making the wrong
thing impossible instead of forbidden.

**Not every seam is closed this way, and one deliberately is not.** `IJwtSigningService` is public and
implementable directly, so a provider that bypasses the framework base class also bypasses the derived
`kid`, the load-time key validation and the active-signer self-test. The mitigation there is a runtime
one: a registered signing service that does not implement one of the optional capability interfaces
(the self-test, or signing-key producibility) records a startup warning naming the concrete type,
rather than skipping either check silently. That is a weaker guarantee than the three above, and it is
a known asymmetry rather than a considered exception.

**`internal` plus `InternalsVisibleTo` is a correctness boundary, not a security one.** The assemblies
are not strong-named and the attribute matches on simple assembly name alone, so anything that can
choose its own assembly name can satisfy a friend grant. It is enough to stop an accidental
implementation; it is not a trust boundary and must never be relied on as one.

**`InternalsVisibleTo` can never serve a third party.** It names first-party assemblies at build time
only, so any capability a third-party package needs must be expressed on the public surface. That is
why the sanitizing-logger interface and the JWK thumbprint helper are public: a provider package
referencing only core has no other way to reach them. Attempting to solve a third-party need with a
friend grant is the mistake this rule exists to prevent — it can serve exactly one named package, and
never the next one without a new core release.

**Three friend grants to shipped packages, each a reviewed exception.** The file-system provider
reuses core's POSIX `stat`/`lstat` interop rather than forking security-critical, ABI-fragile P/Invoke
that has already needed a security fix once. The Windows provider reuses core's process-identity
helper for access-denied diagnostics. The conformance kit needs to construct store keys so a third
party can derive the fixtures from their own test project without any grant of their own. All three
ship in lockstep with core. The rule around them: **anything expressible through core's public surface
must use it** — these are not a pattern to copy.

**The enumerated public extension surface is the SemVer contract.** What a third party may implement:
the startup verifier, the scope repository, the discovery document provider, the client repository,
the client registration and credential interfaces, a client secret hasher (via the abstract base), the
client registration validator, the two store backing contracts, the client authenticator, and a
signing provider via the abstract signing base and its signer type. Everything else public is
consume-only. Adding to this list is a minor version; changing anything on it is a major one. The
question asked of every new public member before it lands is whether it can be changed later without a
breaking change.

**The sanitizing logger is inject-only by convention, backed by a startup gate.** The interface is
public so provider packages can constructor-inject it, and it is a marker over `ILogger<T>` with no
members of its own. A host registering its own implementation before the framework's would shadow
redaction for every framework service, which is why a hard-failing gate runs ahead of every other
startup check and rejects an unexpected open-generic implementation or any closed-generic override.
Making the concrete wrapper public and sealed would turn "do not implement this" into something the
type system enforces, and remains available as a later hardening step.

**Coordinator interfaces grow by adding members outright, not by splitting into capability
interfaces.** Capability splitting is refused: it multiplies the interfaces a backend must discover,
makes "does this store support X?" a runtime type test on the hot path, and pushes protocol branching
into third-party code. The honest state of the alternative — growing by default interface methods that
throw — is that pre-1.0 it has never been exercised: the one time a sixth member was needed it was
added outright, and every implementer changed in the same release. Treat the refusal of capability
interfaces as settled and the growth mechanism as unproven.

**The conformance kit is the last resort, not the sanctioned path.** It ships as its own package so a
third party needs no friend grant, and it covers only what the CLR cannot make structurally true —
whether an operation is atomic, whether a fault fails closed, whether a revocation is complete.
Anywhere the wrong thing can be made unrepresentable instead, it is. A kit, a startup validator or an
analyzer diagnostic still requires the implementer to know the tool exists, so none of them may
substitute for a structural fix that was actually available.

## Tried, didn't work

- **A third-party-implementable store protocol.** The original shipped contract let a consumer
  implement the whole redemption protocol; the correctness-bearing invariants a naive implementation
  could violate while compiling outnumbered the one thing a third party actually wanted to vary. The
  full reversal is in `token-stores.md`; it is listed here because it is the case that produced the
  house pattern.
- **A friend grant as a substitute for public contracts.** The Azure Key Vault provider's first
  attempt at reaching core's signing helpers. It works for exactly one first-party package and can
  never serve a third party. Public contracts with internal crypto is the fix.
