# Startup verification

How the framework's own startup checks run: the single runner, the public `IStartupVerifier` and
`IStartupActivator` seams, and the internal gate phase ahead of them. Implementing a check is
`docs/reference/startup-verification.md`.

## Decisions in force

**Three disjoint collections inside one `StartAsync`, and no host can reach the ordering.**
`StartupVerificationHostedService` is the framework's only startup-check `IHostedService`. It drains
`IEnumerable<IStartupVerificationGate>`, then `IEnumerable<IStartupVerifier>`, then
`IEnumerable<IStartupActivator>`. Because every phase runs inside one `StartAsync`,
`HostOptions.ServicesStartConcurrently` cannot reach the ordering, and no registration order puts a
check ahead of an earlier phase — they are not in the same list.

**Cheap checks run before anything does work.** The activator phase does not run when a verifier
failed, so an application with a broken issuer never opens a connection to a key vault before being
told about it. Membership is mechanical: **a check that resolves and
calls only what the framework itself registered is an `IStartupVerifier`; one resolving or calling
anything the framework did not register is an `IStartupActivator`**. Resolving counts — a constructor
is code. Accepted cost: aggregation is per phase, so a cheap failure and an activator failure need two
restarts. Registering as `IStartupCheck` fails startup; MS.DI never enumerates a base service type, so
it would silently never run.

**Order within a phase is not a guarantee, and a check needing another's work asks for it.**
`ISigningKeyRing.EnsureInitializedAsync` is idempotent for exactly this reason: the client-repository
activator validates against the advertised algorithms, so it calls it rather than assuming it runs
second. That is what "make the dependency structural" means here, and it answers any future request
for an ordering knob.

**Gates are `internal` and the collection is closed; there is exactly one.**
`SanitizingLoggerRegistrationGate` — the check that nothing has shadowed the open-generic
`ISanitizingLogger<>` — is the sole `IStartupVerificationGate`. A gate collection third parties
structurally cannot register into is what makes "nothing logs through an unverified sanitizing
logger" true rather than advised. A collection, not an optional singleton, so a second needs no
reshape.

**The gate ships from the same registration call as the runner.** Both come from
`AddZeeKayDaAuthCore()`, which is public and which provider packages call directly — a host can reach
a fully-wired signing configuration without ever calling `AddZeeKayDaAuth()`, and registering the
gate there is what stops phase 1 passing vacuously in that configuration.

**Nothing is logged, and no check is constructed, until every gate has passed.** The runner holds no
logger of its own; gates report through the context and never log; gate warnings are buffered until
the gate phase ends; and the check collections are *resolved inside* `StartAsync` rather than
constructor-injected, because constructing a check runs its constructor and a constructor can log —
`ISanitizingLogger<T>` is public precisely so provider packages can inject it.

**Failures aggregate within a phase, including unexpected ones.** Every check in a phase runs even
after an earlier one failed, and all `AddFailure` results surface in one
`ZeeKayDaConfigurationException`, so an operator fixes N misconfigurations per restart instead of one.
An *unexpected* exception is recorded as `startup.verifier_failed` and the phase continues; it used
to abort and discard everything aggregated, so one buggy check hid every genuine error beside it.
Root causes travel as the aggregate's `InnerException` — an `AggregateException` when several threw.

**A check that could not complete fails closed, and its code survives.** A thrown
`ZeeKayDaConfigurationException` is absorbed verbatim into the context, keeping stable codes such as
`signing.self_test_failed` that operator alerting keys on; `AggregatedFailures` is non-empty by
construction, so absorbing can never become a silent swallow. Anything else becomes
`startup.verifier_failed`, naming `ex.GetType().FullName` and **never `ex.Message`** — an arbitrary
exception message is untrusted text, and `ZeeKayDaConfigurationFailure.Message` is a plain public-API
string that neither by-key redaction nor `RedactedExceptionWrapper` can reach. The same rule binds
verifier authors. `OperationCanceledException` is rethrown unchanged when the token is signalled, so
a cancelled deployment is not reported as a configuration fault. A warning that fails to log — most
often a template/args arity mismatch, which throws from the logging framework's formatter and is
outside the verifier call's `try` — becomes `startup.warning_log_failed` rather than crashing
`StartAsync` unattributed and discarding the run's genuine failures.

**These seams complement `IValidateOptions<T>`; they do not replace it.** Anything decidable
synchronously from options values stays an options validator. These exist for the three things that
structurally cannot live there: async I/O, a check needing a DI scope, and a check whose whole
purpose is a side effect. Not a second front door for options validation.

**A mutable accumulator, not a returned result.** An implementer calls `AddFailure` or `AddWarning`
in whichever branch they are already in; a pass-through check has an empty method body. Real checks
warn *and* fail, or warn twice, from one dependency resolution, which a result record needs a
composite type to express. The context is fresh per invocation, so findings are attributable and no
check can read, mutate, or clear another's.

**Every invocation gets its own `AsyncServiceScope`, supplied by the runner.** "Constructor-inject
only genuine singletons; resolve anything scoped from `scopedServices`" is the shape of the interface
rather than a remark on two classes. It also keeps a `GetRequiredService` failure inside
`VerifyAsync`, after `ValidateOnStart()`'s friendlier options messages have had their chance to win.

**Execution order is DI registration order and is not expressible in the contract.** `Name` is log
attribution only. There is no `Priority`, no `Order`, and no ordering attribute — a security refusal,
not a simplification: any number a check can declare, a third party can declare too. Disjoint
collections is the version of this that cannot be gamed.

**The runner owns every log call, under the producing check's own category.** It resolves
`ISanitizingLogger<>` reflectively over the check's runtime type through the existing open-generic
registration, so entries carry `MyPackage.MyVerifier`, not the runner. Template and args reach the
sink unformatted, so structured backends index them and by-key redaction acts on them as at any other
call site. The runner's prefix placeholder is `{ErrorCode}`, never `{Code}`: `code` is a redaction key
elsewhere, and `{Code}` would silently redact every startup warning's discriminator in production.

**The level is data spanning the whole `LogLevel` range, chosen at the call site.** The same check
records `Warning` in Development, `Critical` for a deliberate non-Development override, and
`Information` where the message is informational. There is no suppression path and no operator knob,
and no check can downgrade a failure to a warning — `AddFailure` and `AddWarning` are distinct.

**`ZEEKAYDA0002` requires a compile-time-constant message template, including on `AddWarning`.** The
analyzer matches `AddWarning` by symbol — containing type, then `messageTemplate` by name — because
its *first* string argument is `code`, so the `Log*` path's "first string is the template" rule would
check the wrong argument. It binds first-party code only (`IsPackable=false`, reached by
`ProjectReference`). `AddFailure` is deliberately uncovered: its message is not a log template and
by-key redaction never applies to it. The runner's own call composes a constant prefix with the
check's already-unformatted template and carries the single scoped suppression.

**Failure `Code` strings are public API contract.** Preserved verbatim when every hand-rolled check
migrated; they cannot change without a major bump.

**No per-check timeout.** A hung check hangs a host not yet serving traffic, which fails closed.
Every in-tree check is microsecond-scale in-memory work or a call whose transport imposes its own
timeout. `CancellationToken` is on `VerifyAsync`, so a deadline can be added without touching it.

**Startup verification is not a health check.** `IHealthCheck` answers "healthy right now,
repeatedly," and reports `Unhealthy`; this subsystem answers "configured correctly at all," and
refuses to start before Kestrel accepts a connection. Re-running activators — client-secret hashing,
a real vault sign — is actively wrong. A check wanting a health entry implements both interfaces.

**The signing key ring activator resolves its ring lazily and no-ops when there is none.**
`SigningKeyRingStartupVerifier` resolves `ISigningKeyRing` from `scopedServices` and returns silently
when absent, so a host registering only the signing-key health check still starts. When a ring *is*
registered it forces `EnsureInitializedAsync` — the one-time source read, set build, and signer
self-test — so a misconfigured key fails the host rather than the first request. There is no optional
capability interface to skip past: the self-test is inside the ring, and `ISigningKeyRing` is
framework-sealed, so no registered ring can be missing it. A host serving the protocol endpoints must
have one at all; `SigningKeyRingPresenceValidator` is the cheap-phase check that says so.

**Two instances of one check type register with plain `AddSingleton`.** `TryAddEnumerable`
deduplicates by implementation type and would silently drop the second, which is why the per-store
in-memory checks — one per registration call, each capturing its own store name and
`allowOutsideDevelopment` — are added directly. The log category is the shared type, so the instance
`Name` tells them apart. Store presence and in-memory gating are in `token-stores.md`.

**No check's warning is suppressed because another check failed.** Warnings log inline during a
phase; failures surface only in the exception thrown after it, so a warning can appear *ahead of* the
failure that aborts startup. Accepted: the host refuses to start either way. Warnings buffered from a
gate that already passed are flushed before a later gate aborts, rather than discarded with it.

## Tried, didn't work

- **One hand-rolled `IHostedService` per check, with the sanitizing-logger check registered first.**
  The shipped model for roughly twelve checks. Its ordering guarantee was a comment next to an
  `AddHostedService` call, breakable by a host setting `HostOptions.ServicesStartConcurrently = true`
  or by a contributor reordering registrations, and its scope-resolution discipline lived in
  `<remarks>` on two classes so every new check had to rediscover it. Honest cost of the reversal:
  one runner is now a shared failure mode for every check, where a bug in one hosted service used to
  affect one check.
