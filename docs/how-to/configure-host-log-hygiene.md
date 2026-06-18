---
title: "Configure host-level log hygiene"
description: "How to prevent sensitive OAuth parameters from appearing in ASP.NET Core host logs outside ZeeKayDa.Auth's redaction boundary."
parent: "How-to Guides"
nav_order: 5
---

*Added in Unreleased.*

ZeeKayDa.Auth includes a `SecretSanitizingLogger` wrapper that intercepts every log call made by
the library's own services and redacts known-sensitive OAuth parameters — `client_secret`,
`code_verifier`, `Authorization`, `access_token`, `refresh_token`, and others — before they reach
the underlying log sink. In addition, all logged exceptions are unconditionally wrapped in
`RedactedExceptionWrapper`, replacing the exception `Message` with the fixed placeholder
`[exception message redacted by SecretSanitizingLogger]` before the exception reaches any log sink.

> ⚠️ **Warning: The library's redaction boundary covers only ZeeKayDa.Auth's own internal logging.**
> ASP.NET Core's `UseHttpLogging()`, Kestrel's connection logging, W3CLogger, Application Insights
> request telemetry, and custom exception-handling middleware all emit log entries entirely outside
> this wrapper. Any sensitive value those components capture — including the `Authorization` header
> or a `client_secret` posted in a form body — will reach your log sinks verbatim unless you take
> the steps described in this guide.

## What ZeeKayDa.Auth does and does not cover

| Logging surface | Covered by `SecretSanitizingLogger`? |
|---|---|
| ZeeKayDa.Auth internal structured logs | Yes — values for sensitive keys are replaced with `[REDACTED]` |
| Exception messages on logged exceptions | Yes — covered unconditionally; all logged exceptions are wrapped in `RedactedExceptionWrapper` and their `Message` is replaced with a fixed placeholder |
| ASP.NET Core `UseHttpLogging()` | No |
| Kestrel connection/request logging | No |
| W3CLogger | No |
| Application Insights request telemetry | No |
| Exception-handling middleware | No |
| Your own application code calling `ILogger<T>` directly | No |

## 1. Do not enable request-body logging on OAuth endpoints

`UseHttpLogging()` can be configured to log the request body. Because token endpoint requests
(`/connect/token`) send credentials as `application/x-www-form-urlencoded` form fields — including
`client_secret` and `code_verifier` — enabling body logging on those routes will write plaintext
credentials to your logs.

**If you need `UseHttpLogging()` for other routes, limit it explicitly:**

```csharp
// Register the middleware but apply it per-route, not globally.
app.UseHttpLogging();

// Then, on the routes where you want logging:
app.MapGet("/api/some-safe-endpoint", handler)
   .WithHttpLogging(HttpLoggingFields.All);

// Do NOT apply WithHttpLogging to ZeeKayDa.Auth endpoints.
// app.MapZeeKayDaAuth() registers routes under the issuer path;
// leave those routes without WithHttpLogging.
app.MapZeeKayDaAuth();
```

If you call `app.UseHttpLogging()` globally without per-route scoping, disable body logging in the
`HttpLoggingOptions`:

```csharp
builder.Services.AddHttpLogging(logging =>
{
    // Omit RequestBody and ResponseBody from the logged fields.
    logging.LoggingFields = HttpLoggingFields.RequestHeaders
                          | HttpLoggingFields.ResponseHeaders
                          | HttpLoggingFields.ResponseStatusCode;
});

app.UseHttpLogging();
app.MapZeeKayDaAuth();
```

> 💡 **Tip:** `HttpLoggingFields.RequestBody` and `HttpLoggingFields.ResponseBody` are the fields
> that write credential material. Removing them still lets you log headers, status codes, and
> durations, which are useful for diagnostics without being security-sensitive.

## 2. Redact the Authorization header at the host level

The token endpoint accepts `client_secret_basic` credentials as an HTTP `Authorization: Basic …`
header. `UseHttpLogging()` logs request headers by default. Redact the `Authorization` header
before it is written to the log:

```csharp
builder.Services.AddHttpLogging(logging =>
{
    // Log request headers, but redact Authorization.
    logging.LoggingFields = HttpLoggingFields.RequestHeaders
                          | HttpLoggingFields.ResponseStatusCode;

    // Headers not in RequestHeaders are suppressed; adding Authorization here
    // explicitly marks it for redaction (shown as "[Redacted]" in the log output).
    logging.RequestHeaders.Remove("Authorization");
});
```

`HttpLoggingOptions.RequestHeaders` is an allowlist: only headers explicitly listed are logged as
their actual value. Headers absent from the list are logged as `[Redacted]`. Removing
`Authorization` from the set (or simply not adding it) ensures the header value is never written
to the log.

> ⚠️ **Warning:** The `Authorization` header is not in the default `RequestHeaders` allowlist in
> ASP.NET Core 8+, so the default configuration already redacts it. Confirm this remains true for
> the version of ASP.NET Core you are targeting and do not add `"Authorization"` back to the
> allowlist.

## 3. Suppress Kestrel's detailed request logging in production

Kestrel emits connection-level and request-level debug logs under the `Microsoft.AspNetCore.Server.Kestrel`
category. These logs do not typically include header or body values, but they do include raw URLs
which may contain sensitive query parameters on authorization endpoints.

Suppress below `Warning` in production:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore.Server.Kestrel": "Warning"
    }
  }
}
```

## 4. Guard exception-handling middleware

ASP.NET Core's developer exception page and any custom exception middleware may log or render
exception details — including the `HttpContext`, which carries the full request including headers
and form fields. Do not enable the developer exception page in production, and ensure your
production exception handler does not log `HttpContext` or `HttpRequest` objects:

```csharp
if (app.Environment.IsDevelopment())
{
    // Developer exception page is safe in development only.
    app.UseDeveloperExceptionPage();
}
else
{
    // In production, use a minimal error handler that does not log request details.
    app.UseExceptionHandler("/error");
}
```

If you write a custom exception handler that logs exceptions, log only the exception itself — not
`context.Request.Form`, `context.Request.Headers`, or any property that could contain credential
values.

## 5. Check Application Insights and other telemetry SDKs

Application Insights, OpenTelemetry collectors, and similar SDKs may capture the full `HttpRequest`
as part of a dependency or request telemetry item. Consult the documentation for your telemetry
SDK and configure it to:

- Exclude `Authorization` and `client_secret` from captured request properties.
- Disable request-body capture on OAuth endpoints.

For Application Insights specifically, use a `TelemetryInitializer` to scrub sensitive properties
before they are sent:

```csharp
public sealed class OAuthTelemetrySanitizer : ITelemetryInitializer
{
    public void Initialize(ITelemetry telemetry)
    {
        if (telemetry is RequestTelemetry request)
        {
            // Remove the Authorization header from captured telemetry.
            request.Properties.Remove("Authorization");
        }
    }
}
```

Register the initializer in DI:

```csharp
builder.Services.AddSingleton<ITelemetryInitializer, OAuthTelemetrySanitizer>();
```

> 💡 **Tip:** The pattern shown above is a starting point. Your specific telemetry SDK and data
> model will determine exactly which properties to scrub. Review the captured telemetry in a
> staging environment before deploying to production.

## Summary

| Action | Prevents |
|---|---|
| Avoid `HttpLoggingFields.RequestBody` on OAuth routes | `client_secret`, `code_verifier`, and other form fields in logs |
| Remove `Authorization` from `HttpLoggingOptions.RequestHeaders` | Token endpoint `Basic` credentials in HTTP logs |
| Set Kestrel log level to `Warning` in production | Verbose connection noise; URL-embedded parameters |
| Use a non-verbose production exception handler | Full request state (headers, form) in exception logs |
| Sanitize telemetry SDK captured properties | Credentials appearing in APM or tracing back-ends |

## Opting out of exception message sanitization in development

Exception message sanitization is active by default for all environments. If you need to see
original exception messages in your log output during local development, call
`DisableExceptionSanitizing()` on the `ZeeKayDaAuthBuilder` returned by `AddZeeKayDaAuth`:

```csharp
var auth = builder.Services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "http://localhost:5000";
    options.AllowInsecureIssuer = true;
});

auth.DisableExceptionSanitizing();
```

When `DisableExceptionSanitizing()` is active, ZeeKayDa.Auth emits a `LogLevel.Warning` at startup
as a reminder that exception messages will not be redacted.

> ⚠️ **Warning: `DisableExceptionSanitizing()` is for development environments only.**
> Never call it in a production configuration. Exception messages can contain credential values or
> other sensitive state that would reach your log sinks verbatim. Use
> `appsettings.Development.json` environment separation to ensure this call never reaches
> production:

```csharp
// Program.cs — guard with an environment check so the opt-out never reaches production
if (builder.Environment.IsDevelopment())
{
    auth.DisableExceptionSanitizing();
}
```

## Compile-time enforcement inside ZeeKayDa.Auth

In addition to the runtime steps above, ZeeKayDa.Auth ships Roslyn analyzer rules that enforce
log-hygiene requirements at build time for code inside the `ZeeKayDa.*` namespace. `ZEEKAYDA0001`
prevents `ILogger<T>` from being injected directly (bypassing `SecretSanitizingLogger`), and
`ZEEKAYDA0002` prevents interpolated strings containing sensitive identifiers from being passed to
`Log*` methods (which would embed credential values before the redaction layer can act). See the
[Analyzer rules reference](../reference/analyzer-rules.md) for the full rule definitions,
violation examples, and suppression guidance.

## See also

- [Analyzer rules reference](../reference/analyzer-rules.md) — ZEEKAYDA0001 and ZEEKAYDA0002
  compile-time log-hygiene rules
- [Implement a custom extension point](implement-custom-extension-points.md) — security contracts
  for custom hashers and authenticators
- [Configure ZeeKayDa.Auth](configure-zeekayda-auth.md) — register the framework and the minimum
  required options
- [HttpLogging in ASP.NET Core](https://learn.microsoft.com/aspnet/core/fundamentals/http-logging/) — Microsoft's reference for `UseHttpLogging` and `HttpLoggingFields`
