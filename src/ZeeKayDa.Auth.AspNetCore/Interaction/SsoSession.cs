using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The claim types the framework mints into the SSO session cookie, in the reserved <c>zkd:</c>
/// namespace that is stripped from every host-supplied principal.
/// </summary>
internal static class SsoSessionClaimTypes
{
    /// <summary>The SSO session identifier. Stable from sign-in to sign-out.</summary>
    public const string SessionId = "zkd:sid";

    /// <summary>When the user last authenticated, as Unix seconds.</summary>
    public const string AuthTime = "zkd:auth_time";

    /// <summary>An authentication method reference. One claim per value.</summary>
    public const string Amr = "zkd:amr";
}

/// <summary>The framework's view of an established SSO session, read back from the session cookie.</summary>
internal sealed record SsoSessionState
{
    public required string SessionId { get; init; }

    public required string Subject { get; init; }

    public required DateTimeOffset AuthTime { get; init; }

    public required IReadOnlyList<string> Amr { get; init; }
}

/// <summary>
/// Reads and mints the SSO session, which <em>is</em> the <c>zkd.session</c> cookie: there is no
/// server-side record.
/// </summary>
/// <remarks>
/// The cookie is rewritten on every promotion against session fixation; the session identifier
/// survives re-authentication of the same subject, so what is bound to it stays bound.
/// </remarks>
internal sealed class SsoSession(TimeProvider timeProvider)
{
    private const string SubjectClaimType = "sub";

    /// <summary>The established session, or <see langword="null"/> without a readable identifier and subject.</summary>
    public async Task<SsoSessionState?> ReadAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var result = await context.AuthenticateAsync(ZeeKayDaCookies.Session).ConfigureAwait(false);
        if (!result.Succeeded || result.Principal is null)
            return null;

        var sessionId = result.Principal.FindFirstValue(SsoSessionClaimTypes.SessionId);
        var subject = ReadSubject(result.Principal);
        if (string.IsNullOrEmpty(sessionId) || string.IsNullOrEmpty(subject))
            return null;

        return new SsoSessionState
        {
            SessionId = sessionId,
            Subject = subject,
            AuthTime = ReadAuthTime(result.Principal),
            Amr = result.Principal.FindAll(SsoSessionClaimTypes.Amr).Select(claim => claim.Value).ToArray(),
        };
    }

    /// <summary>Writes a fresh session cookie, keeping the session identifier when the subject is unchanged.</summary>
    public async Task<SsoSessionState> PromoteAsync(
        HttpContext context,
        SessionSubject sessionSubject,
        IReadOnlyList<string> authenticationMethods)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(sessionSubject);
        ArgumentNullException.ThrowIfNull(authenticationMethods);

        var subject = sessionSubject.Value;
        var current = await ReadAsync(context).ConfigureAwait(false);
        var sessionId = current is not null && string.Equals(current.Subject, subject, StringComparison.Ordinal)
            ? current.SessionId
            : StoreKeyGenerator.Generate();

        var authTime = timeProvider.GetUtcNow();
        var state = new SsoSessionState
        {
            SessionId = sessionId,
            Subject = subject,
            AuthTime = authTime,
            Amr = [.. authenticationMethods],
        };

        await context.SignInAsync(
                ZeeKayDaCookies.Session,
                BuildSessionPrincipal(state),
                new AuthenticationProperties { IsPersistent = false })
            .ConfigureAwait(false);

        return state;
    }

    /// <summary>Exactly the claims <see cref="ReadAsync"/> reads, and nothing else.</summary>
    private static ClaimsPrincipal BuildSessionPrincipal(SsoSessionState state)
    {
        Claim[] claims =
        [
            new(SubjectClaimType, state.Subject),
            new(SsoSessionClaimTypes.SessionId, state.SessionId),
            new(SsoSessionClaimTypes.AuthTime, state.AuthTime.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)),
            .. state.Amr.Select(value => new Claim(SsoSessionClaimTypes.Amr, value)),
        ];

        return new ClaimsPrincipal(new ClaimsIdentity(claims, ZeeKayDaCookies.Session));
    }

    private static string? ReadSubject(ClaimsPrincipal principal) =>
        principal.FindFirstValue(SubjectClaimType) is { Length: > 0 } subject ? subject : null;

    /// <summary>Reads <c>auth_time</c>; unreadable is infinitely old, so <c>max_age</c> re-authenticates.</summary>
    private static DateTimeOffset ReadAuthTime(ClaimsPrincipal principal)
    {
        var value = principal.FindFirstValue(SsoSessionClaimTypes.AuthTime);

        return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : DateTimeOffset.MinValue;
    }
}
