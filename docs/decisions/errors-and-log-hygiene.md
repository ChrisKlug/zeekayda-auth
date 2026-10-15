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

**Options validation fails in the same shape, all at once.** Every framework options validator
derives from the public `ZeeKayDaOptionsValidator<T>`, which throws `ZeeKayDaConfigurationException`
with every failure its subclass returned, never `ValidateOptionsResult.Fail`; the options factory lets it through. A code is
`configuration.` + the option's path in snake_case + the problem, `AuthorizationServerOptions` being
the root (`configuration.issuer.not_https`); a runtime guard for the same mistake uses the same code.
Options are registered with the public `AddZeeKayDaOptions<T>()` or `.ValidateWithZeeKayDa()`, not
`ValidateOnStart()`, which stops at the first throw. `MapZeeKayDaAuth()` and a startup gate read
every registered type and throw one exception with all their failures. The registration is public
so a third-party package gets the same without friend access, and derives its validator from the
same base; one that returns `Fail` instead becomes one `configuration.options_invalid` failure naming
the type, its text only in the inner exception. The check reads each type as its consumers do and, when that fails, runs every validator
on its own, so one that throws never hides the next, a host's own included.

**A failure message never repeats a configured URI's user information, query or fragment.** They
can hold a password or a signed token, and nothing redacts a failure message, so the URI is shown as
scheme, host, port and path only (`ConfiguredUri`), and a value that does not parse is not shown.

**Never copy `ex.Message`; name the exception type instead.** When the framework turns an arbitrary
exception into a reported failure, it records `ex.GetType().FullName` and a fixed description, never
the message text. An exception message is untrusted text that may embed a connection string, a
credential, or a caller-supplied secret, and a configuration failure's `Message` is a plain public-API
string the framework encourages hosts to surface: neither by-key redaction nor exception wrapping can
reach it. This binds every public failure surface, not just startup verification.

**The same rule binds anyone who throws `ZeeKayDaConfigurationException`, and it is a contract, not a
mechanism.** The type is public, so an extension point — a client or scope repository, a signing key
source, a third-party startup check — can throw it, and the framework preserves the `Code` and
`Message` it carries so a provider's own operator alerting keeps working. Provenance is therefore
documented on `ZeeKayDaConfigurationFailure.Message`: the thrower vouches for that text as safe to
print. Enforcing it by type — an internal subtype only friend assemblies can construct, as
`ScopeContractException` does for the one request-time path — was **refused framework-wide**: it would
make a first-class signing-key source or provider package impossible to build outside this repository,
which is wrong for an open-source framework, and any opt-in marker is as available to a careless
author as to a careful one. A third party who launders a vault error through a failure message is on
the same footing as one who logs it directly: their responsibility, checked when the code arrives as a
PR. What the framework owes is that **its own** text never leaks. For a *log call* that is enforced
mechanically, by the analyzers and the sanitizing logger. For a *failure message* it is not enforced
at all yet — no analyzer reads the `ZeeKayDaConfigurationFailure` constructor or `AddFailure`, which
is why five framework sites once violated the rule above with CI green. Closing that gap is #766;
until it lands, this rule is a contract and a review obligation, not a control.

**Where the framework does claim provenance, it carries it in a type, never in the text.** The
provider-options activator quotes the framework's own pin assertions and merely counts everybody
else's. It learns which is which from a framework-written record, keyed by provider name *and*
options type and cleared before the resolution it describes, because
`OptionsValidationException.Failures` is one flat list every validator registered for the options
type contributes to: a marker inside a string proves nothing about who wrote it, and a host
validator opening with the framework's own prefix would have had its text quoted as the framework's.
The prefix survives as a reading aid for a human inspecting that list, and nothing may treat it as
provenance.

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
`Development` options group, with every other switch that weakens security, because it is
configuration data, not a DI registration; the options group has to stay `public` because the root is bound from `IConfiguration`; and the property name is
deliberately explicit and unambiguous so it cannot slip through a configuration review as an
innocuous flag. It is read from the singleton options binding and cannot be toggled at runtime, which
is correct for a security policy switch. It emits a startup warning on every boot when enabled.

**Two analyzer rules, and they belong together.** `ZEEKAYDA0001` forbids injecting `ILogger<T>`
directly in first-party code — everything goes through the sanitizing logger. `ZEEKAYDA0002` requires
a compile-time-constant message template, including on the startup-verification warning API.

**The log-hygiene rules deliberately opt in to generated code.** Treating a file as generated — by
filename, header, attribute or analyzer config — would suppress a security control with no rule ID
anywhere in the diff.

**The wrapper self-exemption is restricted to types declared in core itself.** A friend assembly can
implement the sanitizing-logger interface but cannot use that to exempt itself from the
constant-template rule — the exemption is reserved for the wrapper defined in `ZeeKayDa.Auth`.
Assembly matching is by simple name throughout; see `extension-surface.md` for why that is a
correctness boundary and not a security one.

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

**`zkd_error` codes are public contract: a closed set that tells a client only what the user did or already knows.**
`login_cancelled`, `consent_declined`, `provider_declined`, `account_refused`, on the authorization error redirect beside
an unchanged `access_denied`, for opted-in clients only; none says whether an account exists, which credential failed,
whether a `client_id` exists, or which provider. The token endpoint sends none. A new code is decided here first.

## Tried, didn't work

- **Enumerating suppression syntaxes in the CI script.** The regex-based predecessor tried to
  recognise every way a suppression can be spelled and could not converge — twelve compile-verified
  bypass vectors were found against it. Asking Roslyn and MSBuild for the resolved effective severity
  is the fix; pattern-matching the spellings is not, and should not be re-proposed.
