# Startup verification

How the framework's own startup checks run: the single runner and the public `IStartupVerifier` and
`IStartupActivator` seams. Implementing a check is `docs/reference/startup-verification.md`.

## Decisions in force

**Options first, then two disjoint collections, inside one `StartAsync`; no host can reach the
ordering.** `StartupVerificationHostedService` is the framework's only startup-check `IHostedService`.
It validates every options type registered through `AddZeeKayDaOptions` — no check is trusted against
options that do not validate — then drains `IEnumerable<IStartupVerifier>`, then
`IEnumerable<IStartupActivator>`. Because every phase runs inside one `StartAsync`,
`HostOptions.ServicesStartConcurrently` cannot reach the ordering, and no registration order puts a
check ahead of an earlier phase — they are not in the same list. Only `AddZeeKayDaAuthCore(configure)`
registers the runner; `ValidateWithZeeKayDa()` does not (a host without a server is unsupported).

**Cheap checks run before anything does work.** The activator phase does not run when a verifier
failed, so an application with a broken issuer never opens a connection to a key vault before being
told about it. Membership is mechanical: **a check that resolves and calls only what the framework
itself registered is an `IStartupVerifier`; one resolving or calling anything else is an
`IStartupActivator`**. Resolving counts — a constructor is code. Accepted cost: aggregation is per
phase, so a cheap failure and an activator failure need two restarts.

**Order within a phase is not a guarantee; a check needing another's work asks for it.**
`SigningKeyRing.EnsureInitializedAsync` is idempotent so the client-repository activator can call it
rather than assume it runs second — the answer to any request for an ordering knob.

**The sanitizing logger cannot be substituted, so nothing has to check that it was not.**
`SanitizingLogger<T>` is a public class, so provider packages can inject it, but its only constructor
is `internal`: no other assembly can construct it or derive from it, so no registration — open- or
closed-generic — can supply a logger that skips redaction. The framework registers an internal sealed
subclass open-generic, because the DI container activates only public constructors. Accepted cost: a
host cannot decorate it.

**Checks are constructor-injected, resolved from one scope per phase.** Checks register as scoped —
any other lifetime fails startup (`startup.check_not_scoped`), since it would build the check outside
the scope, silently so in Production. The runner creates one `AsyncServiceScope` per phase and resolves that phase's collection from it, so
**the checks in a phase share a scope**, and no activator is constructed when a verifier failed. A
check injects `IServiceProvider` only to resolve in `VerifyAsync` instead: a dependency that must
wait for an awaited step (the client repository, validated against algorithms the ring reads first);
one whose construction *is* the check (the client-secret hasher); an options type known only at
runtime; or a presence question to a container without `IServiceProviderIsService`. Accepted costs: a
check leaving scoped state broken can cause a misleading second failure on a failing startup; a check
whose constructor throws fails its phase's resolution, so the rest of that phase does not run — it is
still reported, as below, naming the phase rather than the check.

**Failures aggregate within a phase, including unexpected ones.** Every check in a phase runs even
after an earlier one failed, and all `AddFailure` results surface in one
`ZeeKayDaConfigurationException`, so an operator fixes N misconfigurations per restart instead of one.
An *unexpected* exception is recorded as `startup.verifier_failed` and the phase continues, so one
buggy check cannot hide the genuine errors beside it. Each failure is paired, inside the runner, with the exception behind it; the aggregate's
`InnerException` is the one root cause, or an `AggregateException` over the distinct ones. The pairing
stays internal so `ZeeKayDaConfigurationFailure` holds no exception whose message could leak.

**A check that could not complete fails closed, and its code survives.** A
`ZeeKayDaConfigurationException` thrown by a check or its constructor is absorbed verbatim, keeping
stable codes such as `signing.self_test_failed` that operator alerting keys on; `AggregatedFailures` is non-empty by
construction, so absorbing can never become a silent swallow. Anything else becomes
`startup.verifier_failed`, naming `ex.GetType().FullName` and **never `ex.Message`** — an arbitrary
exception message is untrusted text, and `ZeeKayDaConfigurationFailure.Message` is a plain public-API
string that neither by-key redaction nor `RedactedExceptionWrapper` can reach. The same rule binds
verifier authors. `OperationCanceledException` is rethrown unchanged when the token is signalled, so
a cancelled deployment is not reported as a configuration fault. A warning that fails to log — most
often a template/args arity mismatch, which throws from the logging framework's formatter — becomes
`startup.warning_log_failed`, with its root cause, rather than crashing `StartAsync` unattributed and
discarding the run's genuine failures.

**These seams complement `IValidateOptions<T>`; they do not replace it.** Anything decidable
synchronously from options values stays an options validator. These exist for what structurally
cannot live there: async I/O, a check needing a DI scope, a check whose purpose is a side effect.

**A mutable accumulator, not a returned result.** Checks call `AddFailure` or `AddWarning` from any
branch; the context is fresh per invocation, so no check can read, mutate, or clear another's.

**Execution order is DI registration order and is not expressible in the contract.** `Name` is log
attribution only. There is no `Priority`, no `Order`, and no ordering attribute — a security refusal,
not a simplification: any number a check can declare, a third party can declare too. Disjoint
collections is the version of this that cannot be gamed.

**The runner owns every log call, under the producing check's own category.** It resolves
`SanitizingLogger<>` reflectively over the check's runtime type through the existing open-generic
registration, so entries carry `MyPackage.MyVerifier`, not the runner. Template and args reach the
sink unformatted, so structured backends index them and by-key redaction acts on them as at any other
call site. The runner's prefix placeholder is `{ErrorCode}`, never `{Code}`: `code` is a redaction key
elsewhere, and `{Code}` would silently redact every startup warning's discriminator in production.

**The level is data spanning the whole `LogLevel` range, chosen at the call site.** A
development-only resource records `Information` in `Development` and `Critical` for a deliberate
non-`Development` override; anything else records `Warning`. No suppression path, no operator knob,
and no check can downgrade a failure to a warning — `AddFailure` and `AddWarning` are distinct.

**`ZEEKAYDA0002` requires a compile-time-constant message template, including on `AddWarning`.** The
analyzer matches `AddWarning` by symbol — containing type, then `messageTemplate` by name — because
its *first* string argument is `code`, so the `Log*` path's "first string is the template" rule would
check the wrong argument. It binds first-party code only (`IsPackable=false`, reached by
`ProjectReference`). `AddFailure` is deliberately uncovered: its message is not a log template and
by-key redaction never applies to it. The runner's own call composes a constant prefix with the
check's already-unformatted template and carries the single scoped suppression.

**Failure `Code` strings are public API contract**, changeable only in a major bump.

**No per-check timeout.** A hung check hangs a host not yet serving traffic, which fails closed;
in-tree checks are in-memory or bounded by their transport, and `VerifyAsync` takes a token anyway.

**Startup verification is not a health check.** `IHealthCheck` answers "healthy right now,
repeatedly," and reports `Unhealthy`; this subsystem answers "configured correctly at all," and
refuses to start before Kestrel accepts a connection. Re-running activators — client-secret hashing,
a real vault sign — is actively wrong. A check wanting a health entry implements both interfaces.

**The signing key ring activator takes its ring as optional and no-ops when there is none.**
`SigningKeyRingActivator` injects `SigningKeyRing` with a `null` default and returns silently
when absent. When a ring *is* registered it forces `EnsureInitializedAsync` — the source read, set
build, and signer self-test — so a misconfigured key fails the host rather than the first request; the
self-test is inside the framework-sealed ring, so none can skip it. `SigningKeyRingPresenceVerifier` is
the cheap-phase check that a host serving the protocol endpoints has a ring at all.

**A check's type name ends in its phase, and it lives and registers with the feature it checks.**
`*Verifier` is an `IStartupVerifier`, `*Activator` an `IStartupActivator`. Each sits
in its feature's folder and is registered by that feature's call (`WithProviders` the provider
checks, each store call its store's), so a new feature never edits a central list. Exception: a
**presence check** catches that call never being made, so it registers with the defaults in
`AddZeeKayDaAuthCore(configure)` — or `AddZeeKayDaAuth` for the HTTP-side `LoginDispatchVerifier`.

**Two instances of one check type register with plain `AddScoped`.** `TryAddEnumerable`
deduplicates by implementation type and would silently drop the second, so the per-store checks (one
per registration call, each capturing its own store name and opt-out) are added directly. The log
category is the shared type; the instance `Name` tells them apart. Gating is in `token-stores.md`.

**No check's warning is suppressed because another check failed.** A phase collects every failure and
warning first, logs the warnings, then throws, so a phase's warnings appear *ahead of* the failure
that aborts startup. Accepted: the host refuses to start either way.

**Identical failures are reported once.** Two checks can surface the same broken dependency — the
client-repository and key-ring activators both report a failed key source — and that is one problem
for the operator. Failures sharing a `(Code, Message)` collapse; their root causes are all kept.

## Tried, didn't work

- **One hand-rolled `IHostedService` per check, with the sanitizing-logger check registered first.**
  The shipped model for roughly twelve checks. Its ordering guarantee was a comment next to an
  `AddHostedService` call, breakable by a host setting `HostOptions.ServicesStartConcurrently = true`
  or by a contributor reordering registrations, and its scope-resolution discipline lived in
  `<remarks>` on two classes so every new check had to rediscover it. Honest cost of the reversal:
  one runner is now a shared failure mode for every check, where a bug in one hosted service used to
  affect one check.
- **A gate phase proving a public `ISanitizingLogger<T>` interface had not been replaced.** It scanned
  registrations and forced buffered warnings and late check resolution. A logger nothing outside the
  framework can construct removed the failure mode, and the phase with it.
- **A public `IStartupCheck` base for both interfaces.** MS.DI never enumerates a base service type,
  so a check registered as the base silently never ran; catching it needed its own failure code.
