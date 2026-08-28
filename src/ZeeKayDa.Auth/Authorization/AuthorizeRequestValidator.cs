using System.Text.RegularExpressions;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// Validates authorization request parameters using the two-phase model: phase 1 authenticates
/// the redirect target (<c>client_id</c> + <c>redirect_uri</c>) and its failures render locally;
/// only afterwards may phase 2 failures redirect to the client (RFC 6749 §4.1.2.1).
/// </summary>
/// <remarks>
/// Input is the already-extracted parameter multi-map (query for GET, form body for POST) — this
/// type has no HTTP knowledge. Descriptions in produced errors name the offending parameter and
/// never echo its value. Phase-1 failures are deliberately indistinguishable between
/// unknown-client and unregistered-redirect (client enumeration defence).
/// </remarks>
internal sealed partial class AuthorizeRequestValidator
{
    private const string LocalErrorDescription =
        "The client_id or redirect_uri of this request is missing, unknown, or not registered.";

    // RFC 7636 §4.2: 43–128 characters from the unreserved set.
    [GeneratedRegex("^[A-Za-z0-9\\-._~]{43,128}$")]
    private static partial Regex CodeChallengePattern();

    private readonly ValidatedClientResolver _clientResolver;

    public AuthorizeRequestValidator(ValidatedClientResolver clientResolver)
    {
        ArgumentNullException.ThrowIfNull(clientResolver);
        _clientResolver = clientResolver;
    }

    /// <summary>
    /// Validates the request parameters in <paramref name="parameters"/> — a multi-map so that
    /// duplicated parameters remain observable (duplicates are <c>invalid_request</c>).
    /// </summary>
    public async ValueTask<AuthorizeRequestValidationResult> ValidateAsync(
        IReadOnlyDictionary<string, IReadOnlyList<string?>> parameters,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        // ---- Phase 1: authenticate the redirect target. Failures render locally. ----

        if (!TryGetSingle(parameters, "client_id", out var clientId) || string.IsNullOrEmpty(clientId))
            return LocalError();

        var client = await _clientResolver.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (client is null)
            return LocalError();

        if (!TryGetSingle(parameters, "redirect_uri", out var redirectUri) || string.IsNullOrEmpty(redirectUri))
            return LocalError();

        // Reject anything the registration validator forbids and the canonicalizing match below
        // might otherwise wave through — a fragment, userinfo, an IPv6 zone id, or a control/
        // whitespace character that could survive into the Location header (response splitting).
        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out var redirectParsed) ||
            !string.IsNullOrEmpty(redirectParsed.Fragment) ||
            !string.IsNullOrEmpty(redirectParsed.UserInfo) ||
            RedirectUriValidator.HasIpv6ZoneId(redirectUri) ||
            ContainsControlOrWhitespace(redirectUri))
        {
            return LocalError();
        }

        if (!AuthorizeRedirectUriMatcher.TryMatch(redirectUri, client.RedirectUris, out var redirectTarget))
            return LocalError();

        // ---- Phase 2: the redirect target is trusted; failures redirect to it. ----
        // redirectTarget is derived from the registration, never the raw presented string.

        TryGetSingle(parameters, "state", out var state);

        AuthorizeRequestValidationResult.RedirectError Error(string error, string description) =>
            new() { RedirectUri = redirectTarget, Error = error, Description = description, State = state };

        foreach (var (_, values) in parameters)
        {
            // The offending parameter name is attacker-controlled and must never be echoed into
            // error_description — it is redirected to a legitimate client and RFC 6749 §4.1.2.1
            // restricts the value's character set.
            if (values.Count > 1)
                return Error(AuthorizeRequestErrors.InvalidRequest, "A request parameter is duplicated.");
        }

        if (parameters.ContainsKey("request"))
            return Error(AuthorizeRequestErrors.RequestNotSupported, "The request parameter is not supported.");

        if (parameters.ContainsKey("request_uri"))
            return Error(AuthorizeRequestErrors.RequestUriNotSupported, "The request_uri parameter is not supported.");

        if (!TryGetSingle(parameters, "response_type", out var responseType) || string.IsNullOrEmpty(responseType))
            return Error(AuthorizeRequestErrors.InvalidRequest, "The response_type parameter is required.");

        if (!string.Equals(responseType, "code", StringComparison.Ordinal))
            return Error(AuthorizeRequestErrors.UnsupportedResponseType, "Only the code response type is supported.");

        if (!client.AllowedResponseTypes.Contains(ResponseType.Code) ||
            !client.AllowedGrantTypes.Contains(GrantType.AuthorizationCode))
        {
            return Error(AuthorizeRequestErrors.UnauthorizedClient, "The client may not use the authorization code flow.");
        }

        if (TryGetSingle(parameters, "response_mode", out var responseMode) && responseMode is not null
            && !string.Equals(responseMode, "query", StringComparison.Ordinal))
        {
            return Error(AuthorizeRequestErrors.InvalidRequest, "Only the query response mode is supported.");
        }

        // The effective response mode is always query in v1 — the check must run whether or not the
        // parameter was sent, otherwise a client registered without query silently gets its code in
        // the query string by simply omitting response_mode.
        if (!client.AllowedResponseModes.Contains(ResponseMode.Query))
            return Error(AuthorizeRequestErrors.UnauthorizedClient, "The client may not use the query response mode.");

        if (!TryGetSingle(parameters, "scope", out var scope) || string.IsNullOrEmpty(scope))
            return Error(AuthorizeRequestErrors.InvalidScope, "The scope parameter is required.");

        var requestedScopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        // Silent narrowing per RFC 6749 §3.3; the granted set is reported back via the token
        // response's scope parameter. openid must survive the narrowing — v1 is OIDC-only.
        var effectiveScopes = requestedScopes
            .Where(s => client.AllowedScopes.Contains(s, StringComparer.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (!effectiveScopes.Contains("openid", StringComparer.Ordinal))
            return Error(AuthorizeRequestErrors.InvalidScope, "The openid scope is required.");

        if (!TryGetSingle(parameters, "nonce", out var nonce) || string.IsNullOrEmpty(nonce))
            return Error(AuthorizeRequestErrors.InvalidRequest, "The nonce parameter is required.");

        if (!TryGetSingle(parameters, "code_challenge", out var codeChallenge) || string.IsNullOrEmpty(codeChallenge))
            return Error(AuthorizeRequestErrors.InvalidRequest, "The code_challenge parameter is required.");

        if (!CodeChallengePattern().IsMatch(codeChallenge))
            return Error(AuthorizeRequestErrors.InvalidRequest, "The code_challenge parameter is malformed.");

        if (!TryGetSingle(parameters, "code_challenge_method", out var challengeMethod) || string.IsNullOrEmpty(challengeMethod))
            return Error(AuthorizeRequestErrors.InvalidRequest, "The code_challenge_method parameter is required.");

        if (!string.Equals(challengeMethod, "S256", StringComparison.Ordinal))
            return Error(AuthorizeRequestErrors.InvalidRequest, "Only the S256 code challenge method is supported.");

        var prompts = new HashSet<PromptValue>();
        if (TryGetSingle(parameters, "prompt", out var prompt) && !string.IsNullOrEmpty(prompt))
        {
            // Recognised values are collected; unrecognised ones are ignored per OIDC Core
            // §3.1.2.1. Behaviour (login/consent short-circuits) belongs to the interaction
            // stage — validation only enforces syntax and the none-exclusivity rule.
            foreach (var value in prompt.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                switch (value)
                {
                    case "none": prompts.Add(PromptValue.None); break;
                    case "login": prompts.Add(PromptValue.Login); break;
                    case "consent": prompts.Add(PromptValue.Consent); break;
                    case "select_account": prompts.Add(PromptValue.SelectAccount); break;
                }
            }

            if (prompts.Contains(PromptValue.None) && prompts.Count > 1)
                return Error(AuthorizeRequestErrors.InvalidRequest, "The prompt value none cannot be combined with other values.");

            if (client.AllowedPromptValues.Count > 0 && !prompts.IsSubsetOf(client.AllowedPromptValues))
                return Error(AuthorizeRequestErrors.InvalidRequest, "The prompt parameter requests a value the client may not use.");
        }

        TimeSpan? maxAge = null;
        if (TryGetSingle(parameters, "max_age", out var maxAgeRaw) && !string.IsNullOrEmpty(maxAgeRaw))
        {
            // Capped at int.MaxValue seconds (~68 years): larger than any real max_age, and well
            // below the point where TimeSpan.FromSeconds would overflow and throw out of the endpoint.
            if (!long.TryParse(maxAgeRaw, out var maxAgeSeconds) || maxAgeSeconds < 0 || maxAgeSeconds > int.MaxValue)
                return Error(AuthorizeRequestErrors.InvalidRequest, "The max_age parameter is malformed.");

            maxAge = TimeSpan.FromSeconds(maxAgeSeconds);
        }

        return new AuthorizeRequestValidationResult.Valid
        {
            Request = new ValidatedAuthorizeRequest
            {
                Client = client,
                RedirectUri = redirectTarget,
                Scopes = effectiveScopes,
                State = state,
                Nonce = nonce,
                CodeChallenge = codeChallenge,
                CodeChallengeMethod = CodeChallengeMethod.S256,
                Prompts = prompts,
                MaxAge = maxAge,
            },
        };
    }

    private static AuthorizeRequestValidationResult.LocalError LocalError() => new()
    {
        Error = AuthorizeRequestErrors.InvalidRequest,
        Description = LocalErrorDescription,
    };

    private static bool ContainsControlOrWhitespace(string value)
    {
        foreach (var c in value)
        {
            if (char.IsControl(c) || char.IsWhiteSpace(c))
                return true;
        }

        return false;
    }

    private static bool TryGetSingle(
        IReadOnlyDictionary<string, IReadOnlyList<string?>> parameters,
        string name,
        out string? value)
    {
        if (parameters.TryGetValue(name, out var values) && values.Count == 1)
        {
            value = values[0];
            return true;
        }

        value = null;
        return false;
    }
}
