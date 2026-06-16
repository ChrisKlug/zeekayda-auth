# ADR 0006 — Exception Hierarchy Strategy

**Status:** Accepted  
**Date:** 2026-06-07

---

## Context

During the design of the authorization endpoint interaction API (ADR 0005), the need for
well-typed, framework-specific exceptions became clear. At the time of this ADR, the codebase
throws BCL exceptions for every error condition:

| Location | Exception thrown | Condition |
|---|---|---|
| `EndpointRouteHelper.GetIssuerUri` | `InvalidOperationException` | `Issuer` is null/empty at map time |
| `ZeeKayDaAuthServiceCollectionExtensions.AddZeeKayDaAuth` | `ArgumentNullException` | null `services` or `configure` argument |
| `ZeeKayDaAuthBuilderScopeExtensions` (and other builder extensions) | `ArgumentNullException` | null `builder` argument |
| `InMemoryScopeRepository..ctor` | `ArgumentNullException` / `ArgumentException` | null or invalid scope collection |
| `SecurityHeaderValues.ToHeaderValue` | `ArgumentOutOfRangeException` | undefined enum value in exhaustive switch |

This is a maintenance and usability problem: when a consumer catches an `InvalidOperationException`
from `EndpointRouteHelper`, there is no programmatic way to distinguish "ZeeKayDa.Auth threw this
because the framework is misconfigured" from "my own application code threw this because an
object was in an invalid state". Stack traces help, but catch clauses cannot.

The interaction API being designed for ADR 0005 introduces a second category of runtime error:
misuse of the stateful interaction surface (calling continuation methods in the wrong order,
resuming an already-concluded context). These are a different kind of fault — they indicate a
programming error in the host application, not framework misconfiguration — and deserve a
distinct type.

Three approaches were considered:

1. **Custom base class only** — a `ZeeKayDaException : Exception` hierarchy, where every
   framework-thrown exception is a subtype. Developers can write `catch (ZeeKayDaException)` as
   a blanket handler and immediately identify the source in stack traces.

2. **Semantic BCL subtypes** — framework exceptions derive from `InvalidOperationException`,
   `ArgumentException`, etc. Familiar to .NET developers; plays well with existing catch
   blocks that target BCL types.

3. **Both** — a `ZeeKayDaException` base, with subtypes that also extend a BCL semantic type
   (e.g. `ZeeKayDaConfigurationException : ZeeKayDaException, InvalidOperationException`).
   Would provide both a framework-specific blanket handler and BCL compatibility — but C# does
   not support multiple class inheritance, making this option structurally impossible except
   by rooting `ZeeKayDaException` itself in a BCL type.

A related question: should argument-guard exceptions (`ArgumentNullException`,
`ArgumentException`, `ArgumentOutOfRangeException`) also be replaced with custom types?

---

## Decision

### 1. `ZeeKayDaException` is the abstract base for all framework-thrown non-argument exceptions

A new public abstract class is introduced in `ZeeKayDa.Auth`:

```csharp
namespace ZeeKayDa.Auth;

/// <summary>
/// The base class for all exceptions thrown by ZeeKayDa.Auth framework code.
/// </summary>
/// <remarks>
/// This class is never thrown directly. Catch <see cref="ZeeKayDaException"/> as a blanket
/// handler for any ZeeKayDa.Auth framework error, or catch a specific subtype to handle a
/// known failure category.
/// </remarks>
public abstract class ZeeKayDaException : Exception
{
    /// <summary>Initialises a new instance with the specified <paramref name="message"/>.</summary>
    protected ZeeKayDaException(string message) : base(message) { }

    /// <summary>
    /// Initialises a new instance with the specified <paramref name="message"/> and
    /// <paramref name="innerException"/>.
    /// </summary>
    protected ZeeKayDaException(string message, Exception innerException)
        : base(message, innerException) { }
}
```

`ZeeKayDaException` extends `Exception` directly — **not** `InvalidOperationException` or any
other BCL semantic type. The reasoning is in the Rejected Alternatives section.

`protected` constructors are used deliberately. The class is `abstract`; the constructors should
not suggest that `new ZeeKayDaException(...)` is valid. `protected` enforces that only subtypes
can use them.

The conventional parameterless constructor is deliberately omitted from the base and from every
subtype. A framework exception without a message conveys nothing useful to the consumer; every
throw site must provide an actionable message. Omitting the parameterless ctor enforces this at
compile time.

`[Serializable]` and the `protected ZeeKayDaException(SerializationInfo, StreamingContext)`
deserialization constructor are **not included**. The legacy
`SerializationInfo`/`StreamingContext` exception constructor pattern is marked obsolete in .NET 8
(diagnostic `SYSLIB0051`) and binary formatter serialization is unsupported in modern .NET. On
.NET 10+ there is no reason to implement it.

### 2. `ZeeKayDaConfigurationException` for misconfiguration and startup errors

A companion value type carries one structured failure:

```csharp
namespace ZeeKayDa.Auth;

/// <summary>
/// A single configuration rule violation within a <see cref="ZeeKayDaConfigurationException"/>.
/// </summary>
/// <param name="Code">
/// A stable, versioned string identifier for this violation type (e.g.
/// <c>"client.redirect_uri.duplicate"</c>). Codes are part of the public API contract and
/// must not change without a semver-major bump.
/// </param>
/// <param name="Message">A human-readable description of the violation.</param>
public sealed record ZeeKayDaConfigurationFailure(string Code, string Message);
```

```csharp
namespace ZeeKayDa.Auth;

/// <summary>
/// Thrown when the ZeeKayDa.Auth framework is misconfigured or when a required configuration
/// value is absent or invalid at the point where it is first needed.
/// </summary>
/// <remarks>
/// <para>
/// This exception indicates a setup-time error in the host application — missing service
/// registrations, invalid options values, or configuration state that is required for the
/// framework to operate but was not provided. It is not recoverable at runtime; the correct
/// response is to fix the configuration and restart.
/// </para>
/// <para>
/// Most configuration errors are caught earlier by the startup validator
/// (<c>ValidateOnStart()</c> / <see cref="IValidateOptions{TOptions}"/>). This exception covers
/// the residual cases where invalid state is only detectable at the moment the framework
/// needs to use a value — for example, when <c>MapZeeKayDaAuth()</c> is called before
/// <c>AddZeeKayDaAuth()</c>.
/// </para>
/// </remarks>
public class ZeeKayDaConfigurationException : ZeeKayDaException
{
    /// <summary>
    /// Initialises a new instance from one or more structured <paramref name="failures"/>.
    /// </summary>
    /// <param name="failures">
    /// The structured failures. Must be non-empty; each entry carries a stable
    /// <see cref="ZeeKayDaConfigurationFailure.Code"/> and a human-readable message.
    /// </param>
    public ZeeKayDaConfigurationException(params ZeeKayDaConfigurationFailure[] failures)
        : base($"{failures.Length} configuration errors — see AggregatedFailures for details.")
    {
        AggregatedFailures = [..failures];
    }

    /// <summary>
    /// The structured validation failures that contributed to this exception.
    /// Always contains at least one entry.
    /// </summary>
    public IReadOnlyList<ZeeKayDaConfigurationFailure> AggregatedFailures { get; }
}
```

The `params` constructor accepts one or multiple failures with the same call syntax.
`AggregatedFailures` is always non-empty — the `[..failures]` spread creates a defensive copy
so the stored list cannot be mutated by the caller. `Message` always contains the failure count
and directs diagnostics to `AggregatedFailures`; it never exposes individual failure text
directly. Each `ZeeKayDaConfigurationFailure.Code` is a stable, semver-governed string —
test assertions and programmatic handlers should switch on `Code`, not on `Message`.

**Use this exception for:**
- Framework state that is missing because `AddZeeKayDaAuth()` was never called (or was called
  in the wrong order), detected when the framework first needs that state.
- Required services or options that are absent at the point of use — i.e., configuration gaps
  that the startup validator cannot detect because they depend on runtime resolution.
- Invalid framework configuration that is only detectable lazily (e.g. an options value that
  is valid syntactically but incoherent operationally, and the incoherence is only exposed by
  a specific call path).

**Do not use this exception for:**
- Errors that can be caught at startup — those should be `ValidateOptionsResult.Fail(...)` in
  `AuthorizationServerOptionsValidator`, not exceptions.
- Invalid arguments passed to public API methods — those are `ArgumentException` family (see §4).

**Existing throw site to migrate:** `EndpointRouteHelper.GetIssuerUri` currently throws
`InvalidOperationException` when `Issuer` is null or whitespace at map time. That throw site
must be replaced with `ZeeKayDaConfigurationException` (see Full Implementation Surface below).

### 3. `ZeeKayDaInteractionException` for interaction API misuse at runtime

```csharp
namespace ZeeKayDa.Auth;

/// <summary>
/// Thrown when the ZeeKayDa.Auth interaction API is called incorrectly — for example, calling
/// a continuation method without a valid pending interaction context, or providing a result
/// that is inconsistent with the expected interaction step.
/// </summary>
/// <remarks>
/// <para>
/// This exception indicates a programming error in the host application: the interaction API
/// was called in the wrong state or in the wrong order. It is not a recoverable runtime
/// condition; the correct response is to fix the host application code.
/// </para>
/// <para>
/// This exception is deliberately distinct from <see cref="ZeeKayDaConfigurationException"/>.
/// Configuration errors exist at startup/setup time; interaction errors exist at request time.
/// The distinction matters for logging, alerting, and catch-clause granularity.
/// </para>
/// </remarks>
public class ZeeKayDaInteractionException : ZeeKayDaException
{
    /// <summary>Initialises a new instance with the specified <paramref name="message"/>.</summary>
    public ZeeKayDaInteractionException(string message) : base(message) { }

    /// <summary>
    /// Initialises a new instance with the specified <paramref name="message"/> and
    /// <paramref name="innerException"/>.
    /// </summary>
    public ZeeKayDaInteractionException(string message, Exception innerException)
        : base(message, innerException) { }
}
```

**Use this exception for:**
- Calling interaction service methods (e.g. `CompleteLoginAsync`, `CompleteConsentAsync`) when
  there is no pending interaction context for the current request.
- Providing an interaction result that contradicts the pending step type (e.g. returning a
  consent result when the pending step is authentication).
- Resuming an interaction context that has already concluded or has expired.
- Any other violation of the interaction API's documented preconditions where the violation is
  only detectable at request time (not startup time).

**Do not use this exception for:**
- Host-application bugs that manifest as null arguments — those are `ArgumentNullException`.
- Configuration errors — those are `ZeeKayDaConfigurationException`.

### 4. BCL argument-guard exceptions are retained as-is

`ArgumentNullException`, `ArgumentException`, and `ArgumentOutOfRangeException` remain the
correct exception types for method argument validation throughout the framework. These are **not**
replaced or wrapped.

The reasoning:
- They represent **programming errors at a call site** — passing `null` where a value is
  required, passing a value that is out of domain. These are universally understood by .NET
  developers and have well-established test-assertion patterns (`Assert.Throws<ArgumentNullException>`).
- They carry no framework-specific semantic content. The message string already conveys "which
  argument was wrong"; there is no value in re-wrapping them in a `ZeeKayDa*Exception`.
- Replacing them would diverge from the pattern established by the entire .NET ecosystem (BCL,
  ASP.NET Core, Entity Framework) and would surprise developers who expect `null` arguments to
  throw `ArgumentNullException`.

Concretely, the following existing throw sites **remain unchanged**:
- `ArgumentNullException.ThrowIfNull` in `AddZeeKayDaAuth()`, builder extension methods, and
  similar public API entry points.
- `ArgumentException` in `InMemoryScopeRepository..ctor` for null, blank, or duplicate scope
  names.
- `ArgumentOutOfRangeException` in `SecurityHeaderValues.ToHeaderValue` as the exhaustive
  switch guard for undefined enum values.

This boundary is a **formal rule**: if the error is "you passed a bad argument to this method",
use a BCL argument exception. If the error is "the framework is misconfigured" or "you used the
interaction API incorrectly", use a `ZeeKayDa*Exception`.

### 5. Both exception subtypes live in `ZeeKayDa.Auth` (core), not `ZeeKayDa.Auth.AspNetCore`

`ZeeKayDaException`, `ZeeKayDaConfigurationException`, and `ZeeKayDaInteractionException` are
placed in the `ZeeKayDa.Auth` NuGet package (the core library). This means consumers who need
to catch framework exceptions do **not** need to reference `ZeeKayDa.Auth.AspNetCore`.

For example, an application layer that calls the interaction service interfaces (which are defined
in `ZeeKayDa.Auth`) should be able to catch `ZeeKayDaInteractionException` without pulling in
the ASP.NET Core hosting adapter. If the exceptions lived in `ZeeKayDa.Auth.AspNetCore`, the
application layer would be forced to take a transitive web-stack dependency for a pure
domain-level concern.

This is consistent with the layering rule established in ADR 0001 §3: `ZeeKayDa.Auth` has zero
knowledge of ASP.NET Core; `ZeeKayDa.Auth.AspNetCore` depends on `ZeeKayDa.Auth`, never the
reverse.

### 6. Naming convention: `ZeeKayDa` prefix on all custom exception types

All custom exception types follow the `ZeeKayDa*Exception` naming pattern:
- `ZeeKayDaException` — abstract base
- `ZeeKayDaConfigurationException` — configuration errors
- `ZeeKayDaInteractionException` — interaction API misuse

Future exception types introduced as the framework grows (e.g., `ZeeKayDaTokenException` for
token issuance failures, `ZeeKayDaStorageException` for storage layer errors) must follow the
same prefix pattern. This keeps the framework's error types immediately identifiable in stack
traces, IntelliSense, and log aggregators.

### 7. Concrete subtypes are not sealed

`ZeeKayDaConfigurationException` and `ZeeKayDaInteractionException` are not `sealed`. This
allows:
- Future framework releases to introduce more-specific subtypes that inherit from them (e.g., a
  `ZeeKayDaInteractionContextExpiredException : ZeeKayDaInteractionException` would let host
  code distinguish expiry from order violations with a finer-grained catch clause, while not
  breaking existing code that catches `ZeeKayDaInteractionException`).
- Consumer test code to subclass a framework exception type when building test doubles that
  simulate specific failure scenarios.

The abstract base `ZeeKayDaException` prevents direct instantiation of the base but leaves the
concrete subtypes open for extension.

### 8. Namespace placement: root for cross-cutting types, feature namespace for subtypes

Exception classes live in the namespace of the concern they represent:

| Exception | Namespace | Rationale |
|---|---|---|
| `ZeeKayDaException` | `ZeeKayDa.Auth` | Cross-cutting base; consumers need it regardless of feature area |
| `ZeeKayDaConfigurationException` | `ZeeKayDa.Auth` | Cross-cutting; thrown by startup infrastructure, not a specific feature |
| `ZeeKayDaInteractionException` | `ZeeKayDa.Auth` | Cross-cutting; the interaction surface spans multiple features |
| Future subtypes (e.g. `ZeeKayDaTokenException`) | `ZeeKayDa.Auth.Tokens` | Co-located with the feature that throws them |

**Rules:**
- An exception type lives in the same namespace as the feature types it is associated with — **not** in a dedicated `Exceptions/` subfolder or namespace.
- Cross-cutting base types that a consumer might catch without importing any specific feature namespace stay in the `ZeeKayDa.Auth` root.
- A feature-specific subtype (e.g. `ZeeKayDaTokenException : ZeeKayDaInteractionException`) lives alongside its feature's types (e.g. in `ZeeKayDa.Auth.Tokens`). A consumer who works with tokens already has a `using ZeeKayDa.Auth.Tokens;` import and gets the exception type for free.

This mirrors .NET's own pattern (`System.IO.IOException`, `System.Net.WebException`) and avoids a root-namespace explosion as the framework grows.

---

## Full Implementation Surface

The following describes exactly what must be added or modified. No other files are affected by
this ADR.

### New file: `src/ZeeKayDa.Auth/ZeeKayDaException.cs`

```csharp
namespace ZeeKayDa.Auth;

/// <summary>
/// The base class for all exceptions thrown by ZeeKayDa.Auth framework code.
/// </summary>
/// <remarks>
/// This class is never thrown directly. Catch <see cref="ZeeKayDaException"/> as a blanket
/// handler for any ZeeKayDa.Auth framework error, or catch a specific subtype to handle a
/// known failure category.
/// </remarks>
public abstract class ZeeKayDaException : Exception
{
    /// <summary>Initialises a new instance with the specified <paramref name="message"/>.</summary>
    protected ZeeKayDaException(string message) : base(message) { }

    /// <summary>
    /// Initialises a new instance with the specified <paramref name="message"/> and
    /// <paramref name="innerException"/>.
    /// </summary>
    protected ZeeKayDaException(string message, Exception innerException)
        : base(message, innerException) { }
}
```

### New file: `src/ZeeKayDa.Auth/ZeeKayDaConfigurationFailure.cs`

```csharp
namespace ZeeKayDa.Auth;

/// <summary>
/// A single configuration rule violation within a <see cref="ZeeKayDaConfigurationException"/>.
/// </summary>
/// <param name="Code">
/// A stable, versioned string identifier for this violation type (e.g.
/// <c>"client.redirect_uri.duplicate"</c>). Codes are part of the public API contract and
/// must not change without a semver-major bump.
/// </param>
/// <param name="Message">A human-readable description of the violation.</param>
public sealed record ZeeKayDaConfigurationFailure(string Code, string Message);
```

### New file: `src/ZeeKayDa.Auth/ZeeKayDaConfigurationException.cs`

```csharp
namespace ZeeKayDa.Auth;

/// <summary>
/// Thrown when the ZeeKayDa.Auth framework is misconfigured or when a required configuration
/// value is absent or invalid at the point where it is first needed.
/// </summary>
/// <remarks>
/// <para>
/// This exception indicates a setup-time error in the host application — missing service
/// registrations, invalid options values, or configuration state that is required for the
/// framework to operate but was not provided. It is not recoverable at runtime; the correct
/// response is to fix the configuration and restart.
/// </para>
/// <para>
/// Most configuration errors are caught earlier by the startup validator
/// (<c>ValidateOnStart()</c> / <see cref="IValidateOptions{TOptions}"/>). This exception covers
/// the residual cases where invalid state is only detectable at the moment the framework
/// needs to use a value — for example, when <c>MapZeeKayDaAuth()</c> is called before
/// <c>AddZeeKayDaAuth()</c>.
/// </para>
/// </remarks>
public class ZeeKayDaConfigurationException : ZeeKayDaException
{
    /// <summary>
    /// Initialises a new instance from one or more structured <paramref name="failures"/>.
    /// </summary>
    /// <param name="failures">
    /// The structured failures. Must be non-empty; each entry carries a stable
    /// <see cref="ZeeKayDaConfigurationFailure.Code"/> and a human-readable message.
    /// </param>
    public ZeeKayDaConfigurationException(params ZeeKayDaConfigurationFailure[] failures)
        : base($"{failures.Length} configuration errors — see AggregatedFailures for details.")
    {
        AggregatedFailures = [..failures];
    }

    /// <summary>
    /// The structured validation failures that contributed to this exception.
    /// Always contains at least one entry.
    /// </summary>
    public IReadOnlyList<ZeeKayDaConfigurationFailure> AggregatedFailures { get; }
}
```

### New file: `src/ZeeKayDa.Auth/ZeeKayDaInteractionException.cs`

```csharp
namespace ZeeKayDa.Auth;

/// <summary>
/// Thrown when the ZeeKayDa.Auth interaction API is called incorrectly — for example, calling
/// a continuation method without a valid pending interaction context, or providing a result
/// that is inconsistent with the expected interaction step.
/// </summary>
/// <remarks>
/// <para>
/// This exception indicates a programming error in the host application: the interaction API
/// was called in the wrong state or in the wrong order. It is not a recoverable runtime
/// condition; the correct response is to fix the host application code.
/// </para>
/// <para>
/// This exception is deliberately distinct from <see cref="ZeeKayDaConfigurationException"/>.
/// Configuration errors exist at startup/setup time; interaction errors exist at request time.
/// The distinction matters for logging, alerting, and catch-clause granularity.
/// </para>
/// </remarks>
public class ZeeKayDaInteractionException : ZeeKayDaException
{
    /// <summary>Initialises a new instance with the specified <paramref name="message"/>.</summary>
    public ZeeKayDaInteractionException(string message) : base(message) { }

    /// <summary>
    /// Initialises a new instance with the specified <paramref name="message"/> and
    /// <paramref name="innerException"/>.
    /// </summary>
    public ZeeKayDaInteractionException(string message, Exception innerException)
        : base(message, innerException) { }
}
```

### Modified: `src/ZeeKayDa.Auth.AspNetCore/Endpoints/EndpointRouteHelper.cs`

Replace the `InvalidOperationException` throw in `GetIssuerUri` with
`ZeeKayDaConfigurationException`. The updated method:

```csharp
public static Uri GetIssuerUri(IOptions<AuthorizationServerOptions> options)
{
    var issuer = options.Value.Issuer;

    if (string.IsNullOrWhiteSpace(issuer))
    {
        throw new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "configuration.issuer.missing",
                "AuthorizationServerOptions.Issuer must be configured before calling " +
                "MapZeeKayDaAuth(). Ensure AddZeeKayDaAuth() is called with a valid issuer."));
    }

    return new Uri(issuer);
}
```

Add a `using ZeeKayDa.Auth;` directive if not already present. No other changes to this file.

### No changes to: `InMemoryScopeRepository.cs`, `SecurityHeaderValues.cs`, or any extension method

The `ArgumentNullException`, `ArgumentException`, and `ArgumentOutOfRangeException` throw sites
in these files are correct and must not be changed.

---

## Rejected Alternatives

### Rooting `ZeeKayDaException` in `InvalidOperationException`

**Rejected.** `InvalidOperationException` has a precise .NET semantic: "the current state of the
object is not valid for this operation". Rooting `ZeeKayDaException` there would make that
semantic bleed into exceptions whose nature is entirely different — for example,
`ZeeKayDaConfigurationException` is a startup problem, not an invalid object state at the time
of a call. A developer writing `catch (InvalidOperationException)` to handle their own
application's state errors would silently swallow framework configuration exceptions they should
be seeing. Conversely, a developer writing `catch (ZeeKayDaException)` to handle framework
errors would also catch any `InvalidOperationException` from BCL internals that happens to
propagate through a framework method — if `ZeeKayDaException` extended `InvalidOperationException`
and a consumer's global `InvalidOperationException` handler was catching all ZeeKayDa errors,
they would lose the ability to distinguish them. The clean `ZeeKayDaException : Exception`
hierarchy keeps the framework's error taxonomy orthogonal to the BCL taxonomy.

ASP.NET Core itself follows this pattern: `AuthenticationFailureException` extends `Exception`
directly, not `InvalidOperationException`, even though an authentication failure is semantically
an invalid operation from the caller's perspective. The framework identity in the type name is
sufficient to identify the source.

### Rooting `ZeeKayDaConfigurationException` in `InvalidOperationException`
(with `ZeeKayDaException : Exception`)

**Rejected.** Making only the configuration subtype extend `InvalidOperationException` (C# does
not allow multiple base classes; this would mean `ZeeKayDaConfigurationException` could not
also extend `ZeeKayDaException`) would sacrifice the blanket `catch (ZeeKayDaException)` handler
for configuration errors, fragmenting the hierarchy. The primary value of the base class is that
a consumer can catch all framework errors with one clause; splitting configuration errors out of
the hierarchy undermines that entirely.

### A single `ZeeKayDaException` concrete type (no subtypes)

**Rejected.** A single non-abstract exception type with a string message is insufficient for
programmatic handling. A consumer who wants to treat interaction-API misuse differently from
misconfiguration (e.g., returning `HTTP 500` for the former and exiting the process for the
latter) cannot do so without parsing the message string — which is fragile, unversioned, and
explicitly not part of the public API contract. Distinct subtypes give consumers stable,
semver-governed catch targets.

### Wrapping all BCL argument exceptions in `ZeeKayDa*Exception` types

**Rejected.** Replacing `ArgumentNullException` with a custom type provides no value: the error
is "you passed null", which is universally understood, universally tested (every .NET developer
writes `Assert.Throws<ArgumentNullException>`), and not specific to the ZeeKayDa.Auth domain.
Wrapping it would deviate from the entire .NET ecosystem without a meaningful benefit, and would
make the codebase look alien to .NET contributors. BCL argument exceptions are a boundary
contract between the caller and the method; they are not the same category of error as a
misconfigured framework.

### `ZeeKayDaException` as a concrete (non-abstract) type

**Rejected.** If `ZeeKayDaException` is concrete, there is nothing stopping framework code (or
consumer code in test helpers) from throwing it directly. This would break the hierarchy's intent:
framework throw sites should always throw the most specific available type so that catch clauses
can be written at the right granularity. Making the base abstract enforces this at compile time.
The `protected` constructors already prevent external instantiation, but `abstract` additionally
prevents framework code itself from lazily throwing the base type when a more specific subtype
exists or should be added.

---

## Consequences

### Positive

- **Blanket handler:** `catch (ZeeKayDaException)` gives consumers a single clause that catches
  every ZeeKayDa.Auth framework error without requiring knowledge of every subtype. This is
  especially useful for logging middleware and global exception handlers.
- **Programmatic discrimination:** `catch (ZeeKayDaConfigurationException)` vs.
  `catch (ZeeKayDaInteractionException)` allows consumers to handle misconfiguration (typically
  process-exit severity) separately from interaction API misuse (typically request-error
  severity) without string parsing.
- **Immediate identifiability in stack traces:** Exception type names beginning with `ZeeKayDa`
  make the library's origin unambiguous in logs and error reports. There is no need to inspect
  the namespace or message text to know that ZeeKayDa.Auth is the source.
- **Core-package placement:** Catching framework exceptions does not require a reference to
  `ZeeKayDa.Auth.AspNetCore`. Application-layer code that uses the interaction service interfaces
  can handle `ZeeKayDaInteractionException` without a web-stack dependency.
- **Hierarchy is forward-compatible:** Future subtypes (e.g.,
  `ZeeKayDaInteractionContextExpiredException`) can be added as non-breaking minor-version
  additions. Existing catch clauses targeting the parent type continue to work. New catch clauses
  targeting the specific subtype can be added by consumers who need finer granularity.
- **BCL argument exceptions are undisturbed:** The existing `ArgumentNullException` and
  `ArgumentException` throw sites are correct and remain. No migration of those sites is needed.

### Negative / Trade-offs

- **Does not extend `InvalidOperationException`.** Consumers who currently write
  `catch (InvalidOperationException)` to handle the existing throw in `EndpointRouteHelper` will
  need to update their catch clause after the migration. This is a narrow, internal code path
  that is unlikely to be in consumer catch blocks today, but it is technically a behaviour change
  for any code that catches that specific exception.
- **Two new files per exception type.** Three new `.cs` files are added to `ZeeKayDa.Auth`.
  The implementation surface is small but the file count increases. This is the standard .NET
  pattern (one type per file) and is not a meaningful overhead.
- **Abstract base prevents trivial test construction.** A consumer writing
  `throw new ZeeKayDaException("test")` in test code is not possible. They must use a concrete
  subtype. This is the intended behaviour but may be a minor friction point in tests that want
  to simulate a generic "some framework error occurred" scenario. The mitigation is that
  `ZeeKayDaConfigurationException` is concrete and serves that role adequately.
- **Future subtypes require a framework release.** A consumer who needs a more specific type
  (e.g., a subtype for expired interaction contexts) cannot add it to the framework hierarchy
  without submitting a PR. This is by design — the hierarchy is a public, semver-governed
  API contract — but it means consumer-side subclassing is the only escape hatch until the
  framework ships a more specific type.

---

## Amendments

- **2026-06-10 — Add `AggregatedFailures` and `ZeeKayDaConfigurationFailure`** — Introduced
  `ZeeKayDaConfigurationFailure(string Code, string Message)` as a new sealed record and
  replaced all string-based constructors on `ZeeKayDaConfigurationException` with a single
  `params ZeeKayDaConfigurationFailure[]` constructor. `AggregatedFailures` is always non-empty;
  the constructor stores a defensive copy. `Message` is a fixed string that always directs to
  `AggregatedFailures`. Required by ADR 0007 §6.1; structured `Code` values allow programmatic
  handling and test assertions without string parsing. Resolves #120.

- **2026-06-13 — `ZeeKayDaConfigurationException.Message` is diagnostic-only, not a stable API contract** — The `Message` property is set by the constructor to the fixed format `"{N} configuration errors — see AggregatedFailures for details."` where N is the count of failures; this format is intentional and diagnostic, confirming that failures occurred and directing the reader to `AggregatedFailures` for structured detail. Callers MUST NOT parse or assert on the content of `Message` — it is not versioned, and its exact wording may change in any release (including patch and minor releases) without notice. The stable, semver-governed API for programmatic handling is `AggregatedFailures` and the `Code` field on each `ZeeKayDaConfigurationFailure`; all test assertions and catch-clause logic MUST switch on `Code`, not on any substring of `Message`. `Message` is appropriate for logging and diagnostic output; it is NOT appropriate for user-facing error messages (those should be constructed from individual `ZeeKayDaConfigurationFailure.Message` values) or for programmatic branching. Reference: architecture review finding AA-M9, 2026-06-13. Resolves #159 (partial).
