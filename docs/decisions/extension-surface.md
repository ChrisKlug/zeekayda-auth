# Extension surface

What a third party may implement, what they may only consume, and the mechanics that keep the two
apart. Each seam's own rules live in its topic file; this is the shape they share.

## Decisions in force

**The house pattern: a public seam paired with a closed collection or member.** Where a subsystem has
both a protocol to enforce and a genuinely variable part, the variable part gets a public interface
and the protocol gets a type a third party structurally cannot join. It shows up four times, arrived
at independently:

- **The sanitizing logger.** `SanitizingLogger<T>` is a public class every package can inject, but its
  only constructor is `internal`, so no third party can supply or derive one that skips redaction
  (`startup-verification.md`).
- **Coordinator versus backing store.** The store coordinators are `public` so the ASP.NET Core
  package can inject them, but each carries an `internal` member only a friend assembly can satisfy.
  Publicly consumable, not third-party implementable — the asymmetry actually needed
  (`token-stores.md`).
- **The framework-internal store key.** A backing store receives keys as an opaque struct whose
  constructor is internal, so "hash the handle before you key anything on it" is unrepresentable in
  third-party code rather than documented.
- **Source versus ring.** `ISigningKeySource` is public and third-party-implementable; the
  `SigningKeyRing` it feeds is a sealed class with an internal constructor, so nothing can stand in
  for the ring and skip the startup self-test (`signing-keys.md`).

Reach for this before reaching for a doc comment. It is what the register means by making the wrong
thing impossible instead of forbidden.

**The one seam that was deliberately left open is now closed.** `IJwtSigningService` was public and
implementable directly, so a provider bypassing the framework base class also bypassed the derived
`kid`, the load-time key validation and the active-signer self-test; the mitigation was a runtime
warning naming the concrete type. #511 deleted that contract. `ISigningKeySource` reports data and
lends a signer, and `SigningKeyRing` — which owns selection, `kid` derivation, validation and the
self-test — is a sealed class only the framework constructs, so the bypass is now unrepresentable rather
than warned about.

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
the startup verifier (`IStartupVerifier`) and startup activator (`IStartupActivator`), the claims
provider (`IClaimsProvider`, registered with `AddClaimsProvider<T>()`), the scope repository, the
discovery document provider, the client repository, the client and client-with-credentials interfaces,
a client secret hasher (`IClientSecretHasher`), the client registration validator, the two store
backing contracts, the client authenticator, the token issuer (`ITokenIssuer`, keyed per `TokenKind`),
a signing key source (`ISigningKeySource`) and the signer it lends (`ISigner`), and an options validator
via `ZeeKayDaOptionsValidator<TOptions>`, which returns its coded failures and is registered as
`IValidateOptions<TOptions>`. Everything else public is
consume-only. A framework layer that enforces the rules between a seam and its consumers is a public
sealed class with an internal constructor, never an interface: a host injects it and cannot supply
its own. So are the five interaction services, which complete every protocol step for a page
(`An_interaction_service_cannot_be_supplied_by_a_host`), and `ClientSecrets`, which verifies and pads
(`ClientSecrets_cannot_be_supplied_by_a_host`). Unsealing one is additive. Adding to this list is a
minor version; changing anything on it is a major one. The
question asked of every new public member before it lands is whether it can be changed later without a
breaking change.

**The public API returns `Task`, never `ValueTask`, unless a measurement justifies it.** Every public
async member — interface members, delegates, and members a third party overrides — returns `Task` or
`Task<T>`. A `ValueTask` must be awaited exactly once and never stored, and an implementer or caller who
breaks that compiles cleanly and fails intermittently; a `Task` has no such rule. A specific hot path
moves to `ValueTask` only with a measurement showing the allocation matters. Internal code may use
either, and a member whose type a BCL contract fixes (`IAsyncDisposable.DisposeAsync`) keeps it.

**The sanitizing logger is inject-only, enforced by the type system.** `SanitizingLogger<T>` is a
public class so provider packages can constructor-inject it, with an `internal` constructor so nothing
outside the framework can construct or derive one; any registration of it is therefore the framework's
redacting logger. Accepted cost: a host cannot decorate it.

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

**A caller-supplied repository is validated by the framework, at the point it is read, by one authority.**
`IClientRepository` and `IScopeRepository` are each reached through an internal wrapper —
`ValidatedClientResolver`, `ValidatedScopeCatalog` — that copies what was returned and refuses the copy,
so what was checked is what the protocol sees and a store cannot edit it in between. The wrapper is the
only authority: a shipped in-memory implementation validates nothing of its own, because a second partial
rule set disagrees with the first about codes, about aggregation and about which rules exist at all. They
differ only in how they refuse, and principally: a client verdict is keyed by an attacker-supplied
`client_id`, so a bad registration is served as an unknown client and stays enumeration-safe, while the
scope set is global with no safe partial answer, so it throws and the request becomes `server_error`.

**A wrapped repository must be registered as a singleton, and startup says so.** Both wrappers are
singletons holding the instance they are given, so a scoped or transient repository is captured by the
first request and shared by every later one — a `DbContext` held open for the process. Startup refuses it
(`scopes.repository.lifetime`, `clients.repository.lifetime`) because ASP.NET Core's own scope validation
catches this in Development only, which leaves the unwatched deployment to find it. Per-request
dependencies are resolved inside the repository from an injected `IServiceScopeFactory`.

**Registration lives in Microsoft's namespaces; everything else groups by feature.** Every public `Add…`
and `Map…` extension method is declared in `Microsoft.Extensions.DependencyInjection` or
`Microsoft.AspNetCore.Builder`, so a host's `Program.cs` needs no ZeeKayDa `using` at all. The types a
host or extension author names in its own code sit in the feature namespace they belong to —
`AspNetCore.Interaction`, `Claims`, `Clients`, `Tokens`, `Stores` — and a provider package brings its
own namespace for its options. A host file should need at most two ZeeKayDa `using` directives; no type
is hoisted into the root namespace just to save one.

## Tried, didn't work

- **A third-party-implementable store protocol.** The original shipped contract let a consumer
  implement the whole redemption protocol; the correctness-bearing invariants a naive implementation
  could violate while compiling outnumbered the one thing a third party actually wanted to vary. The
  full reversal is in `token-stores.md`; it is listed here because it is the case that produced the
  house pattern.
- **Interaction services as public interfaces.** Hosts could swap them in DI, so the framework's
  guarantee for each protocol step came to rest on a startup check. Sealed classes with internal
  constructors make the swap unrepresentable instead.
- **A friend grant as a substitute for public contracts.** The Azure Key Vault provider's first
  attempt at reaching core's signing helpers. It works for exactly one first-party package and can
  never serve a third party. Public contracts with internal crypto is the fix.
