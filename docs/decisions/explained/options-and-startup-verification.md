# Options and startup verification, explained

Explains `configuration-and-discovery.md` (the options half; discovery is explained separately) and
`startup-verification.md`. Principles that apply beyond this part are in `principles.md`.

## What it is for

A misconfigured authorization server must refuse to start. It must not fail on its first request,
and it must never run with a weakened setting nobody noticed. The framework checks in two layers:
the options, then the startup checks.

## The options

**The class.** `AddZeeKayDaAuth(o => …)` fills in `AuthorizationServerOptions`: five server-wide
settings on the root and ten nested groups, such as `TokenEndpoint` and `IdToken`. The groups are
get-only, so a host cannot set one to `null` and lose its defaults. A setting's group follows the
start of its discovery-document key (`token_endpoint_*` goes in `TokenEndpoint`); `SecurityHeaders`
and `Logging` are exceptions because they never appear in discovery. It is a large class, but a host
only ever sees it one group at a time.

**The pipeline** is the standard .NET one: the host's lambda runs, `PostConfigureAuthorizationServerOptions`
runs, `AuthorizationServerOptionsValidator` checks, and `ValidateOnStart()` makes all of it happen
at startup rather than on first use. Binding the options from `appsettings.json` works by hand but is
not yet a supported, tested path.

**Options hold data; the builder holds registrations.** Stores, signing keys and hashers are
registered through `ZeeKayDaAuthBuilder`, so a builder method never hides a setting. Options never go
on the wire: discovery copies them into a separate class matching the spec's document.

## The startup checks

Some checks cannot be options validators: they need async I/O (a key vault), a DI scope, or exist
only to log a warning. `StartupVerificationHostedService` runs them before Kestrel accepts traffic:

1. **Gate** (internal, exactly one): proves the sanitizing logger has not been replaced. Nothing
   logs until it passes.
2. **Verifiers** (`IStartupVerifier`): cheap checks touching only what the framework registered.
3. **Activators** (`IStartupActivator`): checks touching what the host supplied, such as the client
   repository or key source. They run only if every verifier passed, so a mistyped issuer never opens
   a Key Vault connection first.

A check reports by calling `AddFailure` or `AddWarning` on a context, which lets it warn and fail
from one pass. The runner collects every failure in a phase and throws once, so an operator fixes
every problem per restart, not one. The runner does all logging on the checks' behalf, so every
message goes through redaction. The phases are the only order; a third party cannot jump the queue.

## What it costs

- A startup rule can live in four places: options validator, gate, verifier or activator.
- A cheap failure and an expensive failure need two restarts to both surface.

## What was rejected

- **One hosted service per check.** The original design; the order the checks ran in was only a
  comment, and `HostOptions.ServicesStartConcurrently` could break it.
- **A flat options class.** It became unmanageable at around 70 fields.
- **Configuring through builder methods.** They cannot be bound from configuration, and they split
  configuration across two surfaces.

## Where it is going

The maintainer walked this part twice, the second time at code level. These are the decisions; each
issue is in M1, before the security audit (#537), and updates this file when it lands.

**Options**

- The options stay the host's input, never rewritten. The post-configurer only freezes; CORS
  canonicalization moves to an internal `CorsAllowlist` beside the endpoints (#799).
- Every collection is frozen, and collections follow one convention everywhere, with no public
  setters (#774). Defaults apply where a value is used, only when the host named none (#779).
- Validation is top-down: each group validates itself through an internal extension method in a
  sibling file and returns its errors; the root coordinates the cross-group rules, named by topic
  (#797). Every error carries a stable code (#796).
- Configuration binding becomes a first-class, tested overload (#798).
- The not-for-production switches move to one `Development` group, one flag per effect, including a
  separate HTTP-loopback CORS flag (#773).

**Startup checks**

- The gate phase goes: the sanitizing logger becomes impossible to replace. The shared public
  `IStartupCheck` base goes. Checks are resolved from one scope per phase and constructor-inject
  their dependencies, so the contract is `Task VerifyAsync(context, cancellationToken)`. The phase
  loop collects first, then logs, then throws, and `ReportEachProblemOnce` names the de-duplication
  (#771).
- Checks are registered by the feature they check, only presence checks centrally (#769), named for
  their phase and placed in their feature's namespace (#770). `ClientRepositoryPresenceValidator`
  becomes a verifier (#772).
- Everything that does not touch HTTP moves to Core, so a Core-only host gets validated options
  (#768). The JWT issuers are registered by the token subsystem (#776); `ThrowIfAlreadyRegistered`
  leaves the public builder (#775).
- Internal DI-built classes use primary constructors without null checks (#800).

**Already done on the #650 branch**: the runner's comments trimmed to the genuine *why*s, its phases
named `…OrThrowAsync` and given what they run, the never-`ex.Message` rule held in one helper, the
end-session path checks moved to their own method, and the post-configurer renamed to the .NET
convention.
