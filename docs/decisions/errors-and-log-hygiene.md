# Errors and log hygiene

The exception hierarchy, and the controls that stop credential material reaching a log sink. Rule
behaviour and suppression syntax are `docs/reference/analyzer-rules.md`; host-side wiring is
`docs/how-to/configure-host-log-hygiene.md`.

## Decisions in force

**Every framework-thrown non-argument exception derives from one abstract root.** `ZeeKayDaException`
extends `Exception` directly, never a BCL semantic type: `InvalidOperationException` means "this
object's current state is wrong for this call", which fits neither a misconfiguration nor a misuse
error, and a host's own `catch (InvalidOperationException)` would swallow framework exceptions it
never meant to handle. ASP.NET Core's own `AuthenticationFailureException` sets the precedent. The
root is `abstract` with `protected` constructors and no parameterless overload, so framework code
cannot lazily throw the base type and every throw site supplies an actionable message. Concrete
subtypes stay unsealed so a finer-grained one can be added without breaking a `catch`.

**BCL argument guards are kept as-is and never wrapped.** The dividing rule is one sentence: *you
passed a bad argument to this method* is `ArgumentNullException`/`ArgumentException`/
`ArgumentOutOfRangeException`; *the framework is misconfigured* or *you used this API wrongly* is a
`ZeeKayDa*Exception`. Every custom type is named `ZeeKayDa*Exception`, and cross-cutting ones stay in
the core root namespace so catching a framework exception never forces a web-stack reference.

**A configuration exception carries structured failures, and `Code` is the contract.** The failure
list is always non-empty and defensively copied; `Code` is stable, SemVer-governed, and what tests
and operator alerting switch on. The composed exception message lists every failure's code and
message so a startup crash is actionable from `ToString()` alone — which means every failure message
is part of a public string, and the rule below binds all of them.

**Never copy `ex.Message`; name the exception type instead.** When the framework turns an arbitrary
exception into a reported failure, it records `ex.GetType().FullName` and a fixed description, never
the message text. An exception message is untrusted text that may embed a connection string, a
credential, or a caller-supplied secret, and a configuration failure's `Message` is a plain public-API
string the framework encourages hosts to surface: neither by-key redaction nor exception wrapping can
reach it. This binds every public failure surface, not just startup verification.

**Two-layer misconfiguration detection is intentional.** Where an error has both a startup validator
and a resolve-time fallback, the validator is the primary layer and the fallback throws if it was
bypassed or never enabled. They are complementary, not competing designs.

**Exception objects are wrapped unconditionally before reaching a log sink.** The sanitizing logger
replaces the message with a fixed placeholder, preserves the stack trace and the whole inner-exception
chain (each wrapped recursively, depth-limited), and exposes the original type name so structured
sinks keep type-based filtering and alerting. Wrapping is never gated on the log state containing a
sensitive key, on the exception type, or on a keyword match against the message: the exception and the
structured state are independent inputs chosen at the call site, so a benign template can carry an
exception whose message embeds a secret, and keyword-matching prose is a heuristic that misses novel
patterns and needs perpetual maintenance. Full suppression was refused for the opposite reason — it
would discard the type, stack and inner chain that diagnosing a production `server_error` from logs
depends on. `BeginScope` carries no exception parameter, so it has no equivalent surface.

**Unscrubbable log state is blocked, not forwarded.** State that is neither a string nor a
key-value sequence cannot be inspected for sensitive pairs, so the sanitizing logger substitutes a
placeholder rather than gamble.

**`code` is a sensitive redaction key, so `{Code}` is a poisoned placeholder name anywhere in the
framework.** A value logged under it silently becomes `[REDACTED]` in production, with no error and
nothing in the diff to notice. The startup runner's `{ErrorCode}` prefix is one instance of a general
rule, not a local quirk.

**The redaction opt-out is public, bindable, and named to read as a risk escalation.** It lives on the
`Logging` options group because it is configuration data, not a DI registration; the options group has
to stay `public` because the root is bound from `IConfiguration`; and the property name is
deliberately explicit and unambiguous so it cannot slip through a configuration review as an
innocuous flag. It is read from the singleton options binding and cannot be toggled at runtime, which
is correct for a security policy switch. It emits a startup warning on every boot when enabled.

**Three analyzer rules, and they belong together.** `ZEEKAYDA0001` forbids injecting `ILogger<T>`
directly in first-party code — everything goes through the sanitizing logger. `ZEEKAYDA0002` requires
a compile-time-constant message template, including on the startup-verification warning API.
`ZEEKAYDA0003` warns that a third-party client repository never references the registration validator;
its category is `Extensibility`, not log hygiene, and it is a different kind of rule, not a third
member of the same family.

**The log-hygiene rules deliberately opt in to generated code.** Treating a file as generated — by
filename, header, attribute or analyzer config — would suppress a security control with no rule ID
anywhere in the diff. `ZEEKAYDA0003` keeps the normal "don't nag about generated code" behaviour,
because it is a Warning-severity extensibility heuristic rather than a security control; promoting it
would mean revisiting that.

**The wrapper self-exemption is restricted to types declared in core itself.** A friend assembly can
implement the sanitizing-logger interface but cannot use that to exempt itself from the
constant-template rule — the exemption is reserved for the wrapper defined in `ZeeKayDa.Auth`. The
same exact-assembly-name reasoning gates `ZEEKAYDA0003`'s in-assembly exemption. Assembly matching is
by simple name throughout; see `extension-surface.md` for why that is a correctness boundary and not
a security one.

**Known gap:** `ZEEKAYDA0002` does not follow a message template through a delegate past its point of
conversion. A template built dynamically and passed as a delegate escapes the rule.

**The CI log-hygiene check is a second, independent control, and the relationship is the point.**
It is a Roslyn/MSBuild-driven script over `src/` and `samples/`, with its own smoke tests, and it does
three things the analyzers cannot: it flags sensitive OAuth/OIDC names used as structured-log
placeholders; it requires a structured justification comment on any in-source suppression of the two
log-hygiene rules, and hard-fails on any diagnostic suppressor naming them; and it asks MSBuild for
each project's *effective severity* and fails if either rule is downgraded anywhere in that
resolution, with no escape hatch at all. The two controls cover for each other's blind spots — the CI
script covered the startup-warning API before the analyzer did, and the script is what stops the
analyzer being switched off. Neither is a substitute for the other. A canary project that must fail to
build, asserted per rule ID, is what proves the analyzers are still firing.

## Tried, didn't work

- **Enumerating suppression syntaxes in the CI script.** The regex-based predecessor tried to
  recognise every way a suppression can be spelled and could not converge — twelve compile-verified
  bypass vectors were found against it. Asking Roslyn and MSBuild for the resolved effective severity
  is the fix; pattern-matching the spellings is not, and should not be re-proposed.
