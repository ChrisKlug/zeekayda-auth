# Options and startup verification, explained

Explains `configuration-and-discovery.md` (the options half; discovery is explained separately) and
`startup-verification.md`.

## What it is for

A misconfigured authorization server must refuse to start. It must not fail on its first request,
and it must never run with a weakened setting nobody noticed. The framework checks in two layers:
the options, then the startup checks.

## Layer 1: options

**What the host writes.** `AddZeeKayDaAuth(o => …)` fills in one class, `AuthorizationServerOptions`.
Server-wide settings sit on the root: `Issuer`, `GrantTypesSupported`, `CorsOrigins`,
`ClockSkewTolerance`, `AllowInsecureIssuer`. Everything else sits in nested groups such as
`TokenEndpoint` and `IdToken`. The groups are get-only, so a host cannot set one to `null` and lose
its defaults.

**Where a setting goes is mechanical.** A setting goes in the group matching the start of its
discovery-document key: `token_endpoint_*` goes in `TokenEndpoint`. `SecurityHeaders` and `Logging`
are the exceptions, because they govern the framework's own behaviour and never appear in discovery.
`ClockSkewTolerance` is on the root on purpose: every clock comparison in the server uses the same
tolerance, instead of each package having its own.

**How it is checked.** It uses the standard .NET options pipeline:

1. The host's lambda runs.
2. `AuthorizationServerOptionsPostConfigurer` canonicalises `CorsOrigins` and makes two collections
   read-only.
3. `AuthorizationServerOptionsValidator` checks everything.
4. `ValidateOnStart()` makes steps 1–3 run at startup rather than on first use.

There is one validator rather than one per group, because the rules cross groups. For example,
allowing `client_credentials` requires a real client authentication method on `TokenEndpoint`.

**Options hold data; the builder holds registrations.** Stores, signing keys and hashers are
registered through `ZeeKayDaAuthBuilder`, which is a thin wrapper over `IServiceCollection` that
extension methods hang off. A builder method never hides a setting. Binding the options from
`appsettings.json` is possible by hand but is not yet a supported, tested path (#798).

**Options never go on the wire.** Discovery copies them into a separate class that matches the
spec's document format, so the options class can be refactored without touching the spec contract.

## Layer 2: startup checks

Some checks cannot be options validators: they need async I/O (reading a key vault), a DI scope,
or they exist only to log a warning. `StartupVerificationHostedService` runs these before Kestrel
accepts traffic, in three phases:

1. **Gate** (internal, exactly one). Proves nothing has replaced the sanitizing logger, which
   strips secrets from the framework's logs. Nothing logs until it passes.
2. **Verifiers** (`IStartupVerifier`). Cheap checks that touch only what the framework registered
   itself, such as "is a signing key ring registered?" or "warn: insecure issuer".
3. **Activators** (`IStartupActivator`). Checks that touch anything the host supplied: the client
   repository, the key source, the scope repository. They run only if every verifier passed, so a
   mistyped issuer never opens a Key Vault connection first.

A check reports by calling `AddFailure` or `AddWarning`. The runner collects every failure in a
phase and throws one exception listing them all, so an operator fixes N problems per restart, not
one. The runner does all logging on the checks' behalf, so every message goes through the secret
redaction. There is no ordering setting. The phases are the only order, so a third party cannot make
its check run first.

## What it costs

- A startup rule can live in four places: options validator, gate, verifier or activator.
- Most of the runner's 329 lines are logging safety: nothing logs before the gate passes, a
  malformed warning cannot crash startup, and exception messages never leak.
- A cheap failure and an expensive failure need two restarts to both surface.

## What was rejected

- **One hosted service per check.** This was the original design. The order the checks ran in was
  only a comment, and `HostOptions.ServicesStartConcurrently` could break it.
- **A flat options class.** It became unmanageable at around 70 fields.
- **Configuring through builder methods.** Those cannot be bound from `appsettings.json`, and they
  split configuration across two surfaces.

## What the walkthrough changed

Each item below is an M1 issue, to be done before the security audit (#537). When one lands, this
file is updated to match.

- #768: redraw the Core/AspNetCore split. Anything not touching HTTP lives in Core, and
  `AddZeeKayDaAuthCore()` stops leaving options unvalidated.
- #769: each startup check is registered by the feature it checks. Only presence checks stay central.
- #770: a check's name ends in its phase (`*Verifier` / `*Activator`), and the check lives in its
  feature's namespace.
- #771: delete the gate phase by making the sanitizing logger impossible to replace, and drop the
  public `IStartupCheck` base.
- #772: `ClientRepositoryPresenceValidator` becomes a verifier, like the other presence checks.
- #773: the not-for-production switches go in one options group, and `AllowInsecureIssuer` stops
  doing two jobs.
- #774: every options collection is frozen after configuration, not two of them.
- #775: the built-in stores register through the same public method a third-party store uses, so
  `ThrowIfAlreadyRegistered` can leave the public builder.
- #776: the default JWT issuers are registered by the token subsystem, not the infrastructure call.
