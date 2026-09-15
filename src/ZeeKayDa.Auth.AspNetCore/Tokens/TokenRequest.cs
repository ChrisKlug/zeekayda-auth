using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tokens;

/// <summary>
/// An authorization-code token request as parsed from the form body (RFC 6749 §4.1.3): every
/// parameter the grant needs, present, single-valued and well-formed. What the values mean —
/// whether the code exists, whether the verifier matches — is decided later, against the store.
/// Whether a <c>code_verifier</c> is required at all depends on the client and the code, neither
/// of which the form alone identifies, so its absence is the grant's to judge.
/// </summary>
internal sealed class TokenRequest
{
    private static readonly Func<IFormCollection, TokenError?>[] Rules =
    [
        NoDuplicatedParameters,
        GrantTypeIsAuthorizationCode,
        CodeIsPresent,
        RedirectUriIsPresent,
        CodeVerifierIsWellFormedWhenPresent,
    ];

    private TokenRequest(IFormCollection form)
    {
        Code = form["code"].ToString();
        RedirectUri = form["redirect_uri"].ToString();
        CodeVerifier = form["code_verifier"].ToString() is { Length: > 0 } verifier ? verifier : null;
        ClientId = form["client_id"].ToString() is { Length: > 0 } clientId ? clientId : null;
    }

    /// <summary>
    /// Parses <paramref name="form"/>, reporting the first rule it breaks. Rules are ordered so
    /// the error a client sees names the earliest thing wrong with its request.
    /// </summary>
    public static bool TryParse(
        IFormCollection form,
        [NotNullWhen(true)] out TokenRequest? request,
        [NotNullWhen(false)] out TokenError? error)
    {
        ArgumentNullException.ThrowIfNull(form);

        error = Rules.Select(rule => rule(form)).FirstOrDefault(problem => problem is not null);
        request = error is null ? new TokenRequest(form) : null;
        return error is null;
    }

    // The offending key is not echoed: it is attacker-chosen, and RFC 6749 §5.2 restricts what
    // an error_description may contain.
    private static TokenError? NoDuplicatedParameters(IFormCollection form) =>
        form.Any(parameter => parameter.Value.Count > 1)
            ? TokenError.InvalidRequest("A parameter must not be repeated.")
            : null;

    private static TokenError? GrantTypeIsAuthorizationCode(IFormCollection form)
    {
        var grantType = form["grant_type"].ToString();

        if (grantType.Length == 0)
            return TokenError.InvalidRequest("The grant_type parameter is required.");

        return string.Equals(grantType, "authorization_code", StringComparison.Ordinal)
            ? null
            : new TokenError(TokenRequestErrors.UnsupportedGrantType, "Only the authorization_code grant type is supported.");
    }

    private static TokenError? CodeIsPresent(IFormCollection form) =>
        form["code"].ToString().Length > 0
            ? null
            : TokenError.InvalidRequest("The code parameter is required.");

    private static TokenError? RedirectUriIsPresent(IFormCollection form) =>
        form["redirect_uri"].ToString().Length > 0
            ? null
            : TokenError.InvalidRequest("The redirect_uri parameter is required.");

    private static TokenError? CodeVerifierIsWellFormedWhenPresent(IFormCollection form)
    {
        var verifier = form["code_verifier"].ToString();

        return verifier.Length == 0 || PkceVerifier.IsWellFormed(verifier)
            ? null
            : TokenError.InvalidRequest("The code_verifier parameter is malformed.");
    }

    /// <summary>The authorization code being exchanged.</summary>
    public string Code { get; }

    /// <summary>The redirect URI the client says the code was delivered to.</summary>
    public string RedirectUri { get; }

    /// <summary>The PKCE verifier, well-formed but not yet checked against the stored challenge, or <see langword="null"/> when absent.</summary>
    public string? CodeVerifier { get; }

    /// <summary>The <c>client_id</c> form parameter, or <see langword="null"/> when absent.</summary>
    public string? ClientId { get; }
}

/// <summary>An <c>error</c> and <c>error_description</c> pair the token endpoint answers with.</summary>
internal sealed record TokenError(string Error, string Description)
{
    public static TokenError InvalidRequest(string description) => new(TokenRequestErrors.InvalidRequest, description);

    public static TokenError InvalidGrant(string description) => new(TokenRequestErrors.InvalidGrant, description);
}
