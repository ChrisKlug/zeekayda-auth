# Options and startup verification, explained

Explains `configuration-and-discovery.md` (the options half; discovery is explained separately) and
`startup-verification.md`. Principles that apply beyond this part are in `principles.md`.

## What it is for

A misconfigured authorization server must refuse to start. It must not fail on its first request,
and it must never run with a weakened setting nobody noticed. The framework checks in two layers:
the options, then the startup checks.

## The options

**The class.** `AddZeeKayDaAuth` fills in `AuthorizationServerOptions`, from a delegate, a
configuration section, or both: four server-wide settings on the root and ten nested groups, such as
`TokenEndpoint` and `Development`. The groups are get-only, so a host cannot set one to `null` and
lose its defaults. A setting's group follows the start of its discovery-document key
(`token_endpoint_*` goes in `TokenEndpoint`); `SecurityHeaders`, `SigningKeys` and `Development` are
exceptions because they never appear in discovery. It is a large class, but a host only ever sees
it one group at a time.

**The pipeline.** The host's configuration runs, then `AuthorizationServerOptionsPostConfigurer`
fills in the one default that depends on other settings and freezes the options: every collection
becomes read-only, and every setter on the root and on each group then throws, so nothing can change
after startup approved it. Each group validates itself in its own `*OptionsValidation.cs` file, and
the root adds the rules that span groups. Every failure carries a stable code.

**Validated together.** Every options type registered through `AddZeeKayDaOptions` is validated
together, so one restart reports every bad setting. The framework does not use `ValidateOnStart()`,
which stops at the first. An extension package registers its own options the same way, and a
validator deriving from `ZeeKayDaOptionsValidator<TOptions>` reports coded failures alongside the
framework's.

**Options hold data; the builder holds registrations.** Stores, signing keys and hashers are
registered through the builder (`ZeeKayDaAuthCoreBuilder`, which the ASP.NET Core
`ZeeKayDaAuthBuilder` extends), so a builder method never hides a setting. Options never go on the
wire: discovery copies them into a separate class matching the spec's document.

## The startup checks

Some checks cannot be options validators: they need async I/O (a key vault), a DI scope, or exist
only to log a warning. `StartupVerificationHostedService` runs them before Kestrel accepts traffic,
in this order, each step running only if the one before passed:

1. **Lifetimes:** every check must be registered as scoped, or startup fails.
2. **Options:** every ZeeKayDa options type is validated together.
3. **Verifiers** (`IStartupVerifier`): cheap checks touching only what the framework registered.
4. **Activators** (`IStartupActivator`): checks touching what the host supplied, such as the client
   repository or key source. A mistyped issuer never opens a Key Vault connection first.

Each phase resolves its checks from one scope. A check reports by calling `AddFailure` or
`AddWarning` on a context, which lets it warn and fail from one pass. The runner collects every
failure in a phase, reports a repeated one once, and throws once, so an operator fixes every problem
per restart, not one. A check that throws is reported by its exception type, never its message. The
runner does all logging on the checks' behalf, through the sanitizing logger, whose constructor is
internal so nothing can replace it. The phases are the only order; a third party cannot jump the
queue.

Checks on the server options and the presence checks are registered centrally in
`AddZeeKayDaAuthCore`; the rest are registered by the feature they check. Everything that does not
touch HTTP lives in Core, so a Core-only host gets the same validation.

## What it costs

- A startup rule can live in three places: options validator, verifier or activator.
- A cheap failure and an expensive failure need two restarts to both surface.

## What was rejected

- **One hosted service per check.** The original design; the order the checks ran in was only a
  comment, and `HostOptions.ServicesStartConcurrently` could break it.
- **A flat options class.** It became unmanageable at around 70 fields.
- **Configuring through builder methods.** They cannot be bound from configuration, and they split
  configuration across two surfaces.
- **A gate phase proving the sanitizing logger was not replaced.** An internal constructor makes
  replacing it impossible, so there is nothing to check.

## What the walkthrough changed

The maintainer walked this part twice, the second time at code level. Everything it decided has
landed in M1: frozen options and one collection convention (#774, #799), defaults applied only when
the host named none (#779), top-down coded validation (#796, #797), configuration binding (#798),
the `Development` group (#773), the startup runner's contract and phases (#771), where checks are
registered and named (#769, #770, #772), Core-only hosts (#768), the token issuers' registration
(#776), an internal `ThrowIfAlreadyRegistered` (#775), and primary constructors for DI-built classes
(#800).
