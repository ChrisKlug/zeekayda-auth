# Startup verification

How the framework's own startup checks run: the single runner, the public `IStartupVerifier` seam,
and the internal gate phase ahead of it. Implementing a verifier is `docs/reference/startup-verification.md`.

## Decisions in force

**Two disjoint collections inside one `StartAsync`, and no host can reach the ordering.**
`StartupVerificationHostedService` is the only startup-check `IHostedService` in the framework. It
drains `IEnumerable<IStartupVerificationGate>` to completion, then `IEnumerable<IStartupVerifier>`.
Because both phases happen inside one `StartAsync`, `HostOptions.ServicesStartConcurrently` cannot
reach into the ordering, and there is no registration order that puts a verifier ahead of a gate —
they are not in the same list. This replaces an ordering that used to be a registration convention.

**Gates are `internal` and the collection is closed; there is exactly one.**
`SanitizingLoggerRegistrationGate` — the check that nothing has shadowed the open-generic
`ISanitizingLogger<>` — is the sole `IStartupVerificationGate`, and is a permanent exception to the
"every check is a verifier" rule. A gate collection third parties structurally cannot register into
is what makes "nothing logs through an unverified sanitizing logger" true rather than advised. It is
a collection rather than a single optional singleton so a second gate needs no internal reshape.

**The gate ships from the same registration call as the runner.** Both come from
`AddZeeKayDaAuthCore()`, so no entry point yields a runner with an empty gate collection.
`AddZeeKayDaAuthCore()` is public and provider packages call it directly, so a host can reach a
fully-wired signing configuration without ever calling `AddZeeKayDaAuth()`; registering the gate
there is what stops phase 1 passing vacuously in that configuration.

**Nothing is logged, and no verifier is constructed, until every gate has passed.** The runner holds
no logger of its own; gates report through the context and never log; gate warnings are buffered and
flushed only after the last gate passes; and `IEnumerable<IStartupVerifier>` is *resolved inside*
`StartAsync` rather than constructor-injected, because constructing a verifier runs its constructor
and a constructor can log — `ISanitizingLogger<T>` is public precisely so provider packages can
inject it.

**Reported failures aggregate; a thrown exception does not.** Every verifier runs even after an
earlier one failed, and all `AddFailure` results across the phase surface in one
`ZeeKayDaConfigurationException`, so an operator fixes N misconfigurations per restart instead of
one. This is safe only because the gate is a separate phase: no verifier depends on another
verifier's success. An *unexpected* exception from a verifier still aborts the phase immediately and
discards failures already aggregated — aggregation is a property of the reporting path, not of the
loop.

**A check that could not complete fails closed, and its published code survives.** A thrown
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

**`IStartupVerifier` complements `IValidateOptions<T>`; it does not replace it.** Anything decidable
synchronously from options values stays an options validator. The verifier seam exists for the three
things that structurally cannot live there: async I/O, a check needing a DI scope, and a check whose
whole purpose is a side effect. It is not a second front door for options validation.

**A mutable accumulator, not a returned result.** An implementer calls `AddFailure` or `AddWarning`
in whichever branch they are already in; a pass-through verifier has an empty method body. Real
checks warn *and* fail, or warn twice, from a single dependency resolution, which a result record
needs a composite type to express. The context is fresh per invocation, so warnings and failures are
attributable to their producer and one verifier cannot read, mutate, or clear another's findings.

**Every invocation gets its own `AsyncServiceScope`, supplied by the runner.** "Constructor-inject
only genuine singletons; resolve anything scoped from `scopedServices`" is the shape of the interface
rather than a remark on two classes. It also keeps a `GetRequiredService` failure inside
`VerifyAsync`, after `ValidateOnStart()`'s friendlier options messages have had their chance to win.

**Execution order is DI registration order and is not expressible in the contract.** `Name` is log
attribution only. There is no `Priority`, no `Order`, and no ordering attribute, and this is a
security refusal, not a simplification: any number a verifier can declare, a third party can declare
too, and the position worth claiming is the one ahead of the sanitizing-logger gate. Two disjoint
collections is the version of this that cannot be gamed. Recurring requests for an ordering knob are
answered by making the dependency structural instead, or by not having one.

**The runner owns every log call, under the producing check's own category.** It resolves
`ISanitizingLogger<>` reflectively over the check's runtime type through the existing open-generic
registration — no logger factory abstraction — so entries carry `MyPackage.MyVerifier`, not the
runner. Template and args reach the sink unformatted, so structured backends index them and by-key
redaction acts on them exactly as at any other framework call site. The runner's own prefix
placeholder is `{ErrorCode}`, never `{Code}`: `code` is a redaction key elsewhere in the framework,
and `{Code}` would silently redact every startup warning's discriminator in production.

**The level is data spanning the whole `LogLevel` range, chosen at the call site.** The same check
records `Warning` in Development, `Critical` for a deliberate non-Development override, and
`Information` where the message is informational (the Key Vault cached-signing memory-residency
notice). There is no suppression path and no operator knob, and no verifier can downgrade a failure
to a warning — `AddFailure` and `AddWarning` are distinct calls.

**`ZEEKAYDA0002` requires a compile-time-constant message template, including on `AddWarning`.** The
analyzer matches `AddWarning` by symbol — containing type, then the `messageTemplate` parameter by
name — because its *first* string argument is `code`, so the `Log*` path's "first string is the
template" rule would check the wrong argument. It binds first-party code only: the analyzer project
is `IsPackable=false` and reaches the framework by `ProjectReference`. `AddFailure` is deliberately
uncovered — its message is not a log template and by-key redaction never applies to it. The runner's
own call composes a constant prefix with the verifier's already-unformatted template and carries the
single scoped suppression; every alternative shape either fails the same rule, flattens the template,
or hand-rolls the BCL's template parser on the redaction path.

**Failure `Code` strings are public API contract.** They were preserved verbatim when every
hand-rolled check migrated, and they cannot change without a major bump.

**No per-verifier timeout.** A hung verifier hangs a host that is not yet serving traffic, which
fails closed. Every in-tree check is either microsecond-scale in-memory work or a call whose
transport already imposes a timeout. `CancellationToken` is already on `VerifyAsync`, so a deadline
can be enforced later without touching the interface.

**Startup verification is not a health check.** `IHealthCheck` answers "healthy right now,
repeatedly," and its natural response is to report `Unhealthy`; this subsystem answers "configured
correctly at all," and its correct response is to refuse to start before Kestrel accepts a
connection. Re-running side-effecting checks — client-secret hashing, a real vault sign — is actively
wrong. A verifier that also wants to contribute a health entry can implement an additional interface.

**The signing key ring verifier resolves its ring lazily and no-ops when there is none.**
`SigningKeyRingStartupVerifier` resolves `ISigningKeyRing` from `scopedServices` and returns silently
when absent, so a host that registers only the signing-key health check still starts. When a ring *is*
registered it forces `InitializeAsync` — the one-time source read, set build, and signer self-test —
so a misconfigured key fails the host rather than the first request. There is no optional capability
interface to skip past: the self-test is inside the ring, and `ISigningKeyRing` is framework-sealed,
so no registered ring can be missing it.

**Two instances of one verifier type register with plain `AddSingleton`.** `TryAddEnumerable`
deduplicates by implementation type and would silently drop the second, which is why the per-store
in-memory checks — one per registration call, each capturing its own store name and
`allowOutsideDevelopment` — are added directly. The log category is the shared type, so the instance
`Name` is what tells the two apart. Store presence and in-memory gating themselves are in
`token-stores.md`.

**No verifier's warning is suppressed because another verifier failed.** Warnings log inline during
the phase; failures surface only in the exception thrown after it. So a warning can appear in the
operator's log *ahead of* the failure that actually aborts startup, and a half-registered
configuration reports its presence failure and its in-memory warning side by side rather than
suppressing the second. Accepted: the host refuses to start either way.

## Tried, didn't work

- **One hand-rolled `IHostedService` per check, with the sanitizing-logger check registered first.**
  The shipped model for roughly twelve checks. Its ordering guarantee was a comment next to an
  `AddHostedService` call, breakable by a host setting `HostOptions.ServicesStartConcurrently = true`
  or by a contributor reordering registrations, and its scope-resolution discipline lived in
  `<remarks>` on two classes so every new check had to rediscover it. Honest cost of the reversal:
  one runner is now a shared failure mode for every check, where a bug in one hosted service used to
  affect one check.
