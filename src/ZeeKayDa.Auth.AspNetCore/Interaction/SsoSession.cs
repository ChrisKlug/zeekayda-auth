using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The claim types the framework mints into the SSO session cookie. All carry the reserved
/// <c>zkd:</c> prefix, and every such claim is stripped from a host-supplied principal before
/// promotion — otherwise a host that copied a claim off an inbound token could hand itself a
/// chosen session identifier.
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

/// <summary>
/// The framework's view of an established SSO session, read back from the session cookie.
/// </summary>
internal sealed record SsoSessionState
{
    public required string SessionId { get; init; }

    public required string Subject { get; init; }

    public required DateTimeOffset AuthTime { get; init; }

    public required IReadOnlyList<string> Amr { get; init; }
}

/// <summary>
/// Reads and mints the SSO session. The session <em>is</em> the <c>zkd.session</c> cookie — there
/// is no server-side session record in v1.
/// </summary>
/// <remarks>
/// <para>
/// The session identifier is ZeeKayDa-minted, random, and stable for the life of the session. It
/// is deliberately <em>not</em> the cookie value: the cookie is rewritten on every promotion for
/// session-fixation resistance, while the identifier survives re-authentication so that anything
/// later bound to it — an authorization code, a refresh token, a revocation list — stays bound
/// across a <c>prompt=login</c>.
/// </para>
/// <para>
/// A new identifier is minted only when there is no live session, or when the subject changes.
/// An identifier derived from the cookie value would break every binding the moment the cookie
/// rotated; one that tracked authentication events rather than the session could never key a
/// denylist.
/// </para>
/// </remarks>
internal sealed class SsoSession(TimeProvider timeProvider)
{
    /// <summary>
    /// The one claim the subject is read from. Every principal promoted here is built by the
    /// framework with it, so the session has a single subject source.
    /// </summary>
    private const string SubjectClaimType = "sub";

    /// <summary>
    /// Reads the established session, or <see langword="null"/> when there is none, when the
    /// cookie cannot be decrypted, or when it carries no identifier and subject — a session
    /// missing either is not a session the framework can reason about.
    /// </summary>
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

    /// <summary>
    /// Promotes a framework-built principal to an SSO session, writing a fresh session cookie.
    /// Reuses the current session's identifier when the subject is unchanged, so that
    /// re-authentication refreshes <c>auth_time</c> without severing existing bindings.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The principal carries no <c>sub</c> — a framework bug, since every caller builds it with one.
    /// </exception>
    public async Task<SsoSessionState> PromoteAsync(
        HttpContext context,
        ClaimsPrincipal principal,
        IReadOnlyList<string> authenticationMethods)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(authenticationMethods);

        var subject = ReadSubject(principal)
            ?? throw new InvalidOperationException("The principal to promote carries no 'sub' claim.");

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
                BuildSessionPrincipal(principal, state),
                new AuthenticationProperties { IsPersistent = false })
            .ConfigureAwait(false);

        return state;
    }

    /// <summary>
    /// Builds the principal the session cookie carries: the host's own claims minus anything in
    /// the reserved namespace, plus the framework's session claims.
    /// </summary>
    private static ClaimsPrincipal BuildSessionPrincipal(ClaimsPrincipal principal, SsoSessionState state)
    {
        // The host's claims are added ahead of the framework's, so a reserved one left in place
        // would win the lookup.
        var claims = principal.Claims
            .Where(claim => !ReservedClaims.IsReserved(claim))
            .ToList();

        claims.Add(new Claim(SsoSessionClaimTypes.SessionId, state.SessionId));
        claims.Add(new Claim(
            SsoSessionClaimTypes.AuthTime,
            state.AuthTime.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));
        claims.AddRange(state.Amr.Select(value => new Claim(SsoSessionClaimTypes.Amr, value)));

        // One identity, not the host's identity collection: the session holds the user the
        // framework authenticated, and a second identity would leave the subject ambiguous.
        return new ClaimsPrincipal(new ClaimsIdentity(claims, ZeeKayDaCookies.Session));
    }

    private static string? ReadSubject(ClaimsPrincipal principal) =>
        principal.FindFirstValue(SubjectClaimType) is { Length: > 0 } subject ? subject : null;

    /// <summary>
    /// Reads <c>auth_time</c>, falling back to <see cref="DateTimeOffset.MinValue"/> when the
    /// claim is missing or unparseable. A session whose authentication time cannot be read is
    /// treated as infinitely old, so a <c>max_age</c> request re-authenticates rather than
    /// accepting an unknown age.
    /// </summary>
    private static DateTimeOffset ReadAuthTime(ClaimsPrincipal principal)
    {
        var value = principal.FindFirstValue(SsoSessionClaimTypes.AuthTime);

        return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : DateTimeOffset.MinValue;
    }
}
