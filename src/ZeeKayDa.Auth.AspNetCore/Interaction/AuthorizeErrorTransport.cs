using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Carries phase-1 authorization error details from the authorize endpoint to the host's error
/// page: an encrypted, short-lived cookie holds the details, the redirect carries only an opaque
/// identifier, and <see cref="ErrorInteraction"/> re-joins the two server-side. Error text never
/// enters a URL, where it would leak into proxy logs and browser history.
/// </summary>
internal sealed class AuthorizeErrorTransport
{
    internal const string CookieName = "zkd.error";
    internal const string QueryParameterName = "error_id";
    private static readonly string DataProtectionPurpose = "ZeeKayDa.Auth:AuthorizeErrorTransport";
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(2);

    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;
    private readonly string? _errorPath;

    public AuthorizeErrorTransport(
        IDataProtectionProvider dataProtectionProvider,
        IOptions<AuthorizationServerOptions> serverOptions,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(dataProtectionProvider);
        ArgumentNullException.ThrowIfNull(serverOptions);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _protector = dataProtectionProvider.CreateProtector(DataProtectionPurpose);
        _timeProvider = timeProvider;
        _errorPath = serverOptions.Value.AuthorizationEndpoint.Interaction.ErrorPath;
    }

    /// <summary>
    /// Attaches the transport cookie for the given error to the response and returns the opaque
    /// identifier to carry on the redirect.
    /// </summary>
    public string CreateAndAttach(HttpContext context, string error, string description)
    {
        var id = StoreKeyGenerator.Generate();

        // Hand-rolled serialization: four fields do not justify a source-generated context.
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("id", id);
            writer.WriteString("error", error);
            writer.WriteString("description", description);
            writer.WriteString("expiresAt", _timeProvider.GetUtcNow() + Lifetime);
            writer.WriteEndObject();
        }

        var protectedValue = _protector.Protect(buffer.ToArray());

        context.Response.Cookies.Append(CookieName, Convert.ToBase64String(protectedValue), new CookieOptions
        {
            HttpOnly = true,
            // Unconditionally Secure: the route group already refuses non-HTTPS except loopback,
            // and a TLS-terminating proxy without UseForwardedHeaders must not silently downgrade
            // the cookie. Loopback development over plain HTTP loses the cookie, which is the
            // visible failure mode we prefer to an invisible hardening loss.
            Secure = true,
            SameSite = SameSiteMode.Lax,
            MaxAge = Lifetime,
            Path = _errorPath, // only invoked when ErrorPath is configured
            IsEssential = true,
        });

        return id;
    }

    /// <summary>
    /// Reads the two halves the transport needs — the cookie and the id from the redirect — or
    /// returns <see langword="false"/> when either is absent.
    /// </summary>
    private static bool TryGetTransportInputs(HttpContext context, out string cookieValue, out string requestedId)
    {
        requestedId = string.Empty;

        if (!context.Request.Cookies.TryGetValue(CookieName, out var cookie) || cookie is null)
        {
            cookieValue = string.Empty;
            return false;
        }

        cookieValue = cookie;

        if (context.Request.Query[QueryParameterName] is not [string id])
            return false;

        if (string.IsNullOrEmpty(id))
            return false;

        requestedId = id;
        return true;
    }

    /// <summary>
    /// Reads and verifies the transport cookie against the request's error identifier. Returns
    /// <see langword="null"/> when absent, expired, undecipherable, or mismatched — never throws
    /// for a malformed inbound value.
    /// </summary>
    public AuthorizationErrorDetails? TryRead(HttpContext context)
    {
        if (!TryGetTransportInputs(context, out var cookieValue, out var requestedId))
            return null;

        string id;
        string error;
        string description;
        DateTimeOffset expiresAt;
        try
        {
            var protectedValue = Convert.FromBase64String(cookieValue);
            var json = _protector.Unprotect(protectedValue);
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            id = root.GetProperty("id").GetString()!;
            error = root.GetProperty("error").GetString()!;
            description = root.GetProperty("description").GetString()!;
            expiresAt = root.GetProperty("expiresAt").GetDateTimeOffset();
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return null;
        }

        if (_timeProvider.GetUtcNow() >= expiresAt ||
            !CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.UTF8.GetBytes(id),
                System.Text.Encoding.UTF8.GetBytes(requestedId)))
        {
            return null;
        }

        return new AuthorizationErrorDetails { Error = error, Description = description };
    }
}
