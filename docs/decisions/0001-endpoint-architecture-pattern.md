# ADR 0001 — Endpoint Architecture Pattern

**Status:** Accepted (amended 2026-06-07)  
**Date:** 2026-05-31

---

## Amendments

| Date | Section | Summary | Reference |
|---|---|---|---|
| 2026-06-07 | §3 Layering | Replaced the ad-hoc "may reference `Microsoft.Extensions.Options`" carve-out with a namespace-level dependency allowlist: the entire `Microsoft.Extensions.*` namespace is permitted; `Microsoft.AspNetCore.*` is prohibited except for an explicitly enumerated whitelist (currently only `Microsoft.AspNetCore.DataProtection.Abstractions`). Retroactively covers the `IDistributedCache` dependency introduced by ADR 0005 §6b and accommodates the `IDataProtectionProvider` / `IMemoryCache` dependencies introduced by ADR 0008. | [#106](https://github.com/ChrisKlug/zeekayda-auth/issues/106) |

---

## Context

ZeeKayDa.Auth is an OpenID Connect identity provider framework targeting .NET 10+. It must expose
several well-known HTTP endpoints mandated by the OIDC and OAuth 2 family of specifications:

- `/.well-known/openid-configuration` — OIDC Discovery 1.0
  ([OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html))
- `/.well-known/oauth-authorization-server` — OAuth 2.0 Authorization Server Metadata
  ([RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) / RFC 9207)
- `/connect/authorize` — Authorization endpoint
- `/connect/token` — Token endpoint
- `/connect/jwks` — JSON Web Key Set endpoint

Two design concerns must be resolved before any endpoint is implemented:

1. **How are individual protocol endpoints structured and discovered internally?**  
   Each endpoint has distinct request-handling logic, but all must be registered onto a single
   `IEndpointRouteBuilder` by a single public call from the consumer.

2. **What is the public registration API surface?**  
   ASP.NET Core has established naming conventions for registration methods. Picking the wrong name
   misleads consumers and is a breaking change to fix later.

A third concern cuts across both: the framework has two NuGet packages with a strict layering rule —
`ZeeKayDa.Auth` (core, no ASP.NET Core knowledge) and `ZeeKayDa.Auth.AspNetCore` (the hosting
adapter). Every design decision must respect this boundary.

---

## Decision

### 1. Endpoint abstraction: internal `IZeeKayDaEndpoint`

A package-internal interface is defined in `ZeeKayDa.Auth.AspNetCore`:

```csharp
internal interface IZeeKayDaEndpoint
{
    void Map(IEndpointRouteBuilder endpoints);
}
```

Each protocol endpoint is an `internal sealed class` that implements this interface and registers
exactly one route (or a small cohesive set of routes for a single protocol concern). The concrete
implementations are registered in DI using `TryAddEnumerable`:

```csharp
services.TryAddEnumerable(
    ServiceDescriptor.Singleton<IZeeKayDaEndpoint, DiscoveryEndpoint>());
// … one call per endpoint class …
```

`MapZeeKayDaAuth()` resolves all `IZeeKayDaEndpoint` registrations from DI and calls `Map` on each:

```csharp
public static IEndpointRouteBuilder MapZeeKayDaAuth(this IEndpointRouteBuilder endpoints)
{
    foreach (var endpoint in endpoints.ServiceProvider
                                      .GetServices<IZeeKayDaEndpoint>())
    {
        endpoint.Map(endpoints);
    }
    return endpoints;
}
```

**The interface is `internal`.** Consumers cannot implement it; they cannot inject arbitrary routes
into the protocol surface. This is an intentional constraint — the fewer surfaces that are public,
the smaller the attack surface and the lower the risk of consumers accidentally violating protocol
invariants. Extension points for behaviour customisation are provided through the options model and
dedicated service interfaces, not by letting consumers replace endpoints wholesale.

### 2. Public registration API: `AddZeeKayDaAuth` + `MapZeeKayDaAuth`

```csharp
// DI registration — ZeeKayDa.Auth.AspNetCore
builder.Services.AddZeeKayDaAuth(options => { … });

// Route registration — ZeeKayDa.Auth.AspNetCore
app.MapZeeKayDaAuth();
```

**`MapZeeKayDaAuth`, not `UseZeeKayDaAuth`.** In ASP.NET Core's established naming convention:

- `Use*` (e.g., `UseAuthentication`, `UseAuthorization`, `UseStaticFiles`) registers a
  **middleware** in the `IApplicationBuilder` pipeline.
- `Map*` (e.g., `MapControllers`, `MapRazorPages`, `MapHealthChecks`) registers **endpoint routes**
  via `IEndpointRouteBuilder`.

ZeeKayDa.Auth registers endpoint routes, not middleware. Using `UseZeeKayDaAuth` would be
semantically incorrect and would mislead consumers into thinking the library inserts a middleware
component rather than registering routable endpoints. The name `MapZeeKayDaAuth` correctly signals
what the method does and aligns with existing ASP.NET Core ecosystem patterns.

### 3. Layering: strict core / AspNetCore boundary

| Concern | Package |
|---|---|
| `AuthorizationServerOptions` | `ZeeKayDa.Auth` |
| `OpenIdConfigurationDocument` | `ZeeKayDa.Auth` |
| `IDiscoveryDocumentProvider` / `DiscoveryDocumentProvider` | `ZeeKayDa.Auth` |
| `IValidateOptions<AuthorizationServerOptions>` implementation | `ZeeKayDa.Auth` |
| `IZeeKayDaEndpoint` interface | `ZeeKayDa.Auth.AspNetCore` |
| Concrete endpoint classes | `ZeeKayDa.Auth.AspNetCore` |
| `AddZeeKayDaAuth()` extension | `ZeeKayDa.Auth.AspNetCore` |
| `MapZeeKayDaAuth()` extension | `ZeeKayDa.Auth.AspNetCore` |

`ZeeKayDa.Auth` has **zero knowledge of ASP.NET Core**. Because the boundary between "generic host
/ runtime extensions" and "ASP.NET Core" is drawn by Microsoft along namespace lines — but with one
well-known historical exception — the rule is encoded as a namespace-level allowlist rather than a
case-by-case judgement call:

- **Permitted (namespace-level):** any package under `Microsoft.Extensions.*`. This namespace is
  the generic-host / runtime-extensions surface; nothing in it carries a transitive dependency on
  ASP.NET Core, and it is usable from console, worker-service, gRPC, MAUI, and test hosts. No
  per-package ADR is required to take a dependency on a `Microsoft.Extensions.*` package.
  Representative examples already used or anticipated: `Microsoft.Extensions.Options`,
  `Microsoft.Extensions.Options.DataAnnotations`,
  `Microsoft.Extensions.DependencyInjection.Abstractions`,
  `Microsoft.Extensions.Logging.Abstractions`,
  `Microsoft.Extensions.Caching.Abstractions` (`IDistributedCache`, per ADR 0005 §6b),
  `Microsoft.Extensions.Caching.Memory` (`IMemoryCache`, per ADR 0008).
- **Permitted (individually whitelisted):** specific `Microsoft.AspNetCore.*` packages that are
  factually host-agnostic despite their naming. The current whitelist is:
  - `Microsoft.AspNetCore.DataProtection.Abstractions` — provides `IDataProtectionProvider` /
    `IDataProtector` (per ADR 0008). This is a historical wart: Data Protection predates the
    `Microsoft.Extensions.*` reorganisation and was never renamed, but the abstractions package
    contains no HTTP, hosting, routing, or middleware types and has no transitive ASP.NET Core
    dependency.

  Any future addition to this whitelist **requires an explicit ADR** justifying why the package is
  host-agnostic in fact, regardless of its namespace.
- **Prohibited:** everything else under `Microsoft.AspNetCore.*` — including but not limited to
  `Microsoft.AspNetCore.Hosting`, `Microsoft.AspNetCore.Http`, `Microsoft.AspNetCore.Routing`,
  `Microsoft.AspNetCore.Mvc`, and the types `HttpContext`, `IApplicationBuilder`, and
  `IEndpointRouteBuilder`. The core library must remain independently testable and usable by any
  host (e.g., a future gRPC or MAUI host).

`ZeeKayDa.Auth.AspNetCore` depends on `ZeeKayDa.Auth`. The reverse dependency is permanently
forbidden.

### 4. Options → discovery document mapping

`AuthorizationServerOptions` is the **configuration class**. It is never serialised directly; doing
so would tightly couple the internal configuration model to the wire format, making either
impossible to evolve independently.

`OpenIdConfigurationDocument` is the **OIDC Discovery 1.0 response model** — a pure record with
`[JsonPropertyName]` attributes matching the specification's field names exactly. All nullable
properties are annotated `[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]` so that
fields the server does not support are omitted from the document rather than emitted as `null`,
which would be incorrect per the spec (absent ≠ null for optional discovery fields).

`IDiscoveryDocumentProvider` (in `ZeeKayDa.Auth`) maps `AuthorizationServerOptions` →
`OpenIdConfigurationDocument`. The `DiscoveryEndpoint` (in `ZeeKayDa.Auth.AspNetCore`) calls this
provider and serialises the result. The endpoint knows nothing about the mapping logic; the provider
knows nothing about HTTP.

### 5. Endpoint URIs derived from the issuer

`authorization_endpoint`, `token_endpoint`, `jwks_uri`, and other endpoint URIs in the discovery
document are derived from `AuthorizationServerOptions.Issuer` as defaults. Derivation uses `Uri`
combination semantics — never string concatenation — to handle trailing slashes and path components
correctly:

| Field | Default (issuer = `https://auth.example.com`) | Default (issuer = `https://auth.example.com/tenant1`) |
|---|---|---|
| `authorization_endpoint` | `https://auth.example.com/connect/authorize` | `https://auth.example.com/tenant1/connect/authorize` |
| `token_endpoint` | `https://auth.example.com/connect/token` | `https://auth.example.com/tenant1/connect/token` |
| `jwks_uri` | `https://auth.example.com/connect/jwks` | `https://auth.example.com/tenant1/connect/jwks` |

Any individual URI can be overridden explicitly via `AuthorizationServerOptions`. This
"derived with explicit override" approach minimises required configuration (a single `Issuer` value
is enough to produce a valid discovery document) while preserving full control. This follows the
convention established by OpenIddict and Duende IdentityServer.

### 5a. Discovery endpoint registration path derived from the issuer path

[OIDC Discovery 1.0 §4.1](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest)
specifies that when the issuer carries a path component, the discovery document URL is constructed
by appending `/.well-known/openid-configuration` to the issuer path, not to the root:

- `https://auth.example.com` → `https://auth.example.com/.well-known/openid-configuration`
- `https://auth.example.com/tenant1` → `https://auth.example.com/tenant1/.well-known/openid-configuration`

The `DiscoveryEndpoint` therefore derives its registration path from `AuthorizationServerOptions.Issuer`
at startup, not hardcoding `/.well-known/openid-configuration`. A root issuer registers at
`/.well-known/openid-configuration`; a path-bearing issuer registers at
`{issuer-path}/.well-known/openid-configuration`.

This is required for RFC 9207 §4 compliance: a client fetching the discovery document from the
spec-mandated URL will confirm that the `issuer` field in the response exactly matches the issuer
used to construct that URL. If the endpoint were always registered at the root, a path-bearing
issuer would produce a document whose `issuer` field does not match the URL from which it was
fetched — a condition that RFC 9207-compliant clients must reject as a potential mix-up attack.

**Rejected alternative:** Reject path-based issuers at startup (validator fails if `Issuer` has a
non-empty path). This would be simpler but would silently prevent a common multi-tenant deployment
pattern and violate the spec for no technical reason. Option B (dynamic path derivation) is
spec-correct and only marginally more complex.

### 6. Fail-fast validation via `IValidateOptions<AuthorizationServerOptions>`

An `IValidateOptions<AuthorizationServerOptions>` implementation lives in `ZeeKayDa.Auth` and
enforces the following rules at startup:

- `Issuer` must be set (non-null, non-empty).
- `Issuer` must be a valid absolute URI.
- `Issuer` must not contain a query string or fragment component (prohibited by
  [OpenID Connect Discovery 1.0 §4.1](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
  and [RFC 8414 §2](https://datatracker.ietf.org/doc/html/rfc8414#section-2)).
- `Issuer` **must use HTTPS**. An HTTP issuer causes a startup failure unless
  `AuthorizationServerOptions.AllowInsecureIssuer = true` is explicitly set. The OIDC spec
  requires the issuer to be an HTTPS URL in production; the explicit opt-in permits only loopback
  HTTP issuers for local development and tests.

`ValidateOnStart()` is called in the `AddZeeKayDaAuth()` extension method (in
`ZeeKayDa.Auth.AspNetCore`), because it is the host layer that understands startup lifecycle. The
validator class itself lives in `ZeeKayDa.Auth` and is registered via `AddOptions` so it can be
tested without a web host.

### 7. RFC 9207 issuer confirmation at response time

[RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207) requires that the `issuer` field in the
discovery document **exactly match** the issuer identifier of the authorisation server. To prevent
any possibility of the serialised document drifting from the live configuration (e.g., if an
`IOptionsSnapshot` were used and a reload occurred between validation and response), the discovery
endpoint resolves `IDiscoveryDocumentProvider` at **response time** and reads
`IOptions<AuthorizationServerOptions>` (not a cached snapshot) so that the `issuer` field in the
response always reflects the current configuration value.

`IOptions<T>` (singleton semantics) is used rather than `IOptionsSnapshot<T>` (scoped) or
`IOptionsMonitor<T>` (observable changes) because the issuer identifier of an authorisation server
is not expected to change at runtime. Changing the issuer at runtime would invalidate all
outstanding tokens and all relying-party registrations — it is operationally equivalent to
standing up a new server. This assumption — that `Issuer` is effectively immutable after startup —
is intentional and is enforced by the fail-fast validator described in §6. If a future use-case
requires runtime reconfiguration, this decision must be revisited and a new ADR written.

### 8. Cache-Control set in the endpoint handler

The discovery endpoint sets `Cache-Control: public, max-age=3600, must-revalidate` (one hour) by
default directly in the endpoint handler, not via middleware, output caching policy, or a response
filter.

This keeps the caching behaviour co-located with the endpoint that owns it, makes it trivially
testable (inspect the response headers in a unit test with no middleware pipeline), and avoids
hidden behaviour from a shared policy that a consumer might inadvertently modify or disable. A
consumer who needs a shorter cache lifetime for their deployment can do so by wrapping
`MapZeeKayDaAuth()` with a route-level metadata attribute — they are not fighting framework
middleware.

---

## Rejected Alternatives

### `UseZeeKayDaAuth` instead of `MapZeeKayDaAuth`

**Rejected.** `Use*` is the ASP.NET Core convention for middleware registration via
`IApplicationBuilder`. ZeeKayDa.Auth registers endpoint routes, not middleware. Naming the method
`UseZeeKayDaAuth` would be semantically incorrect, would imply ordering concerns relative to
`UseRouting` and `UseAuthentication` that do not actually apply, and would require a breaking
rename to correct. `MapZeeKayDaAuth` is unambiguous and consistent with `MapControllers`,
`MapRazorPages`, and `MapHealthChecks`.

### Public `IZeeKayDaEndpoint` interface

**Rejected.** Making the endpoint interface public would allow consumers to add arbitrary routes
into the registered set, bypassing any framework-level invariants (path uniqueness, required
middleware, route conventions). It would also lock the interface into the public API contract,
making any signature change a breaking change. Behaviour extension is provided through options and
dedicated service abstractions, not through endpoint injection.

### Middleware-based routing (single catch-all middleware)

**Rejected.** A catch-all middleware that inspects `HttpContext.Request.Path` and dispatches
manually was considered for simplicity. It was rejected because: (a) it bypasses ASP.NET Core's
built-in endpoint routing, forfeiting authorisation policies, rate limiting, OpenAPI metadata
integration, and endpoint diagnostics for free; (b) it cannot participate in
`IEndpointRouteBuilder` conventions; (c) it makes the routing topology invisible to tooling such
as the endpoint explorer and `dotnet-counters`.

### Serialising `AuthorizationServerOptions` directly

**Rejected.** Serialising the options class directly couples the configuration model to the wire
format. Any internal refactoring of `AuthorizationServerOptions` (renaming a property, changing a
type, adding a computed helper) would risk altering the JSON output — which is a publicly visible,
spec-mandated contract under OIDC Discovery 1.0. The separate `OpenIdConfigurationDocument` record
acts as an explicit, stable serialisation contract that can be evolved independently.

### Output caching middleware for the discovery endpoint

**Rejected.** Using ASP.NET Core's output caching infrastructure for the `Cache-Control` header
was considered. It was rejected because: (a) it introduces an implicit dependency on the output
caching middleware being registered by the consumer, which is not guaranteed; (b) it makes caching
behaviour subject to a consumer's global output caching policy and potentially invisible in code
review; (c) it adds indirection with no meaningful benefit over a direct
`response.Headers.CacheControl` assignment for a single, well-understood endpoint.

---

## Consequences

### Positive

- The internal endpoint interface keeps the protocol surface closed to unintentional extension,
  reducing the risk of consumer-introduced security issues without restricting legitimate
  customisation.
- The strict core/AspNetCore boundary makes `ZeeKayDa.Auth` independently testable and reusable
  by non-web hosts.
- Separating `AuthorizationServerOptions` from `OpenIdConfigurationDocument` allows both the
  configuration API and the wire format to evolve without coupling.
- Fail-fast HTTPS validation means insecure production deployments fail loudly at startup rather
  than silently at first request.
- `MapZeeKayDaAuth` aligns with ASP.NET Core idioms, reducing the cognitive overhead for consumers
  already familiar with the ecosystem.
- Per-endpoint `Cache-Control` assignment is trivially verifiable in unit tests without a running
  pipeline.

### Negative / Trade-offs

- The auto-discovery pattern (resolving all `IZeeKayDaEndpoint` registrations from DI) means that
  the set of registered routes is not visible from a single place in source code. Contributors must
  know to search for `IZeeKayDaEndpoint` implementations. This is mitigated by the `internal`
  visibility — the set is finite, auditable, and cannot be extended from outside the package.
- Using `IOptions<T>` (singleton) rather than `IOptionsSnapshot<T>` means live configuration
  reload of the issuer is not supported. This is an explicit, intentional constraint (see §7
  above). Any future change here requires a new ADR.
- The `AllowInsecureIssuer` escape hatch for HTTP loopback issuers, while necessary for local
  development and integration testing, cannot by itself prove the hosting environment is safe.
  Documentation must clearly mark it as a development-only flag. The explicit, verbose name and
  loopback restriction are the primary safeguards.
- `TryAddEnumerable` ensures that calling `AddZeeKayDaAuth()` twice does not double-register
  endpoints. This is the desired behaviour, but contributors must use `TryAddEnumerable` (not
  `AddSingleton`) consistently for every `IZeeKayDaEndpoint` registration.
