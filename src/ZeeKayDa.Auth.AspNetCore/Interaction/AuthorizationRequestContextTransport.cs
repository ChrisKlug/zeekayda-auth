using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Carries the <see cref="AuthorizationRequestContext"/> across the redirects between
/// <c>/connect/authorize</c> and the response to the client: an encrypted, opaque payload in the
/// <c>zkd.interaction</c> cookie.
/// </summary>
/// <remarks>
/// <para>
/// There is no store behind this and no identifier addresses it. The context authenticates nothing
/// on its own — replay protection belongs to the single-use authorization code — so it needs no
/// server-side identity, and a store would add public API for backends
/// <c>IDistributedCache</c> already covers.
/// </para>
/// <para>
/// Concurrent authorization requests in separate browser tabs are last-one-wins. That follows from
/// correlating through a cookie at all, which is what keeps <c>ReturnUrl</c> out of host code; it
/// is not a consequence of where the payload is kept, and a store would not lift it.
/// </para>
/// </remarks>
internal sealed class AuthorizationRequestContextTransport
{
    internal const string CookieName = "zkd.interaction";

    /// <summary>
    /// The hard lifetime of an interaction. Not sliding: a request gets one window to complete,
    /// not a renewable one.
    /// </summary>
    internal static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(30);

    /// <summary>
    /// The ceiling on the encrypted payload, before Base64. Inbound parameters are deliberately
    /// not length-capped — <c>state</c> is formally unbounded, and a cap would tax honest clients
    /// while merely relocating a careless one's failure. Guarding the outcome instead means an
    /// oversized request fails legibly at the request that caused it, rather than as a header some
    /// proxy rejects on the next hop.
    /// </summary>
    internal const int MaxProtectedPayloadBytes = 8 * 1024;

    private static readonly string DataProtectionPurpose = "ZeeKayDa.Auth:AuthorizationRequestContext";

    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;
    private readonly ChunkingCookieManager _cookies = new();

    public AuthorizationRequestContextTransport(
        IDataProtectionProvider dataProtectionProvider,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(dataProtectionProvider);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _protector = dataProtectionProvider.CreateProtector(DataProtectionPurpose);
        _timeProvider = timeProvider;
    }

    /// <summary>
    /// Encrypts the context onto the response as the interaction cookie, splitting it into chunks
    /// when it does not fit one.
    /// </summary>
    /// <returns>
    /// <see langword="false"/> when the encrypted payload exceeds
    /// <see cref="MaxProtectedPayloadBytes"/>, in which case nothing is written and the caller
    /// must answer <c>invalid_request</c>.
    /// </returns>
    public bool TryWrite(HttpContext context, AuthorizationRequestContext requestContext)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        var protectedValue = _protector.Protect(AuthorizationRequestContextSerializer.Encode(requestContext));
        if (protectedValue.Length > MaxProtectedPayloadBytes)
            return false;

        _cookies.AppendResponseCookie(
            context,
            CookieName,
            Convert.ToBase64String(protectedValue),
            BuildCookieOptions(requestContext.ExpiresAt - _timeProvider.GetUtcNow()));

        return true;
    }

    /// <summary>
    /// Reads the interaction context from the request, reassembling it from chunks. Returns
    /// <see langword="null"/> when the cookie is absent, expired, tampered with, protected under a
    /// key this application cannot read, or written by a different format version — never throws
    /// for a malformed inbound value.
    /// </summary>
    public AuthorizationRequestContext? TryRead(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var cookie = _cookies.GetRequestCookie(context, CookieName);
        if (string.IsNullOrEmpty(cookie))
            return null;

        byte[] payload;
        try
        {
            payload = _protector.Unprotect(Convert.FromBase64String(cookie));
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            return null;
        }

        if (!AuthorizationRequestContextSerializer.TryDecode(payload, out var requestContext))
            return null;

        // The expiry inside the payload is authoritative, not the cookie's own MaxAge: the client
        // controls when it stops sending a cookie, and this is the copy it cannot edit.
        return _timeProvider.GetUtcNow() >= requestContext!.ExpiresAt ? null : requestContext;
    }

    /// <summary>
    /// Removes the interaction cookie and every chunk of it. Called when the flow terminates —
    /// the code is issued, consent is denied, or the request errors out.
    /// </summary>
    public void Delete(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        _cookies.DeleteCookie(context, CookieName, BuildCookieOptions(null));
    }

    private static CookieOptions BuildCookieOptions(TimeSpan? maxAge) => new()
    {
        HttpOnly = true,
        // Unconditionally Secure: the route group already refuses non-HTTPS except loopback, and a
        // TLS-terminating proxy without UseForwardedHeaders must not silently downgrade the
        // cookie.
        Secure = true,
        // Lax, not Strict: the interaction has to survive a top-level GET back from an external
        // identity provider. Not None — nothing here is read from a cross-site POST.
        SameSite = SameSiteMode.Lax,
        // Root path: the host's own login and consent pages read this, and they live wherever the
        // host put them.
        Path = "/",
        MaxAge = maxAge,
        IsEssential = true,
    };
}
