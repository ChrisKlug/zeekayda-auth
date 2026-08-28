using System.Text.RegularExpressions;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// Validates authorization request parameters using the two-phase model: phase 1 authenticates
/// the redirect target (<c>client_id</c> + <c>redirect_uri</c>) and its failures render locally;
/// only afterwards may phase 2 failures redirect to the client (RFC 6749 §4.1.2.1).
/// </summary>
/// <remarks>
/// <para>
/// Input is the already-extracted parameter multi-map (query for GET, form body for POST) — this
/// type has no HTTP knowledge. Descriptions in produced errors name the offending parameter and
/// never echo its value. Phase-1 failures are deliberately indistinguishable between
/// unknown-client and unregistered-redirect (client enumeration defence).
/// </para>
/// <para>
/// Phase 2 is expressed as an ordered rule table rather than a straight-line chain of guards:
/// each rule is a small named predicate returning a <see cref="Problem"/> or
/// <see langword="null"/>, and the first problem wins. Order is significant — a rule may rely on
/// values an earlier rule parsed into the <see cref="RequestContext"/>.
/// </para>
/// </remarks>
internal sealed partial class AuthorizeRequestValidator
{
    private const string LocalErrorDescription =
        "The client_id or redirect_uri of this request is missing, unknown, or not registered.";

    // RFC 7636 §4.2: 43–128 characters from the unreserved set.
    [GeneratedRegex("^[A-Za-z0-9\\-._~]{43,128}$")]
    private static partial Regex CodeChallengePattern();

    private static readonly Func<RequestContext, Problem?>[] Phase2Rules =
    [
        NoDuplicatedParameters,
        RequestObjectIsRefused,
        RequestUriIsRefused,
        ResponseTypeIsPresent,
        ResponseTypeIsCode,
        ClientMayUseTheCodeFlow,
        ResponseModeIsQueryWhenPresent,
        ClientMayUseTheQueryResponseMode,
        ScopeIsPresent,
        EffectiveScopeIncludesOpenId,
        NonceIsPresent,
        CodeChallengeIsPresent,
        CodeChallengeIsWellFormed,
        CodeChallengeMethodIsS256,
        PromptValuesAreCoherent,
        PromptValuesArePermittedForTheClient,
        MaxAgeIsWellFormed,
    ];

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

        var target = await AuthenticateRedirectTargetAsync(parameters, cancellationToken).ConfigureAwait(false);
        if (target is null)
            return LocalError();

        // The redirect target is now trusted, so from here failures are delivered to the client.
        var context = new RequestContext(parameters, target.Client);
        var problem = Phase2Rules.Select(rule => rule(context)).FirstOrDefault(p => p is not null);

        TryGetSingle(parameters, "state", out var state);

        return problem is not null
            ? new AuthorizeRequestValidationResult.RedirectError
            {
                RedirectUri = target.RedirectUri,
                Error = problem.Error,
                Description = problem.Description,
                State = state,
            }
            : new AuthorizeRequestValidationResult.Valid
            {
                Request = Build(context, target.RedirectUri, state),
            };
    }

    // ---- Phase 1: authenticate the redirect target. Failures render locally. ----

    /// <summary>
    /// Resolves and authenticates the client and its redirect target, or <see langword="null"/>
    /// when either is missing, unknown, or not registered — a distinction the caller must not be
    /// able to observe.
    /// </summary>
    private async ValueTask<RedirectTarget?> AuthenticateRedirectTargetAsync(
        IReadOnlyDictionary<string, IReadOnlyList<string?>> parameters,
        CancellationToken cancellationToken)
    {
        if (!TryGetSingle(parameters, "client_id", out var clientId) || string.IsNullOrEmpty(clientId))
            return null;

        var client = await _clientResolver.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (client is null)
            return null;

        if (!TryGetSingle(parameters, "redirect_uri", out var redirectUri) || string.IsNullOrEmpty(redirectUri))
            return null;

        if (!IsRedirectUriShapeAcceptable(redirectUri))
            return null;

        return AuthorizeRedirectUriMatcher.TryMatch(redirectUri, client.RedirectUris, out var redirectTarget)
            ? new RedirectTarget(client, redirectTarget)
            : null;
    }

    /// <summary>
    /// Rejects the redirect-URI forms that the canonicalizing match would otherwise wave through:
    /// a fragment, userinfo, an IPv6 zone id, or a control/whitespace character that could survive
    /// into the <c>Location</c> header (response splitting).
    /// </summary>
    private static bool IsRedirectUriShapeAcceptable(string redirectUri)
    {
        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out var parsed))
            return false;

        return string.IsNullOrEmpty(parsed.Fragment)
            && string.IsNullOrEmpty(parsed.UserInfo)
            && !RedirectUriValidator.HasIpv6ZoneId(redirectUri)
            && !ContainsControlOrWhitespace(redirectUri);
    }

    // ---- Phase 2 rules, evaluated in the order declared in Phase2Rules. ----

    private static Problem? NoDuplicatedParameters(RequestContext context)
    {
        // The offending parameter name is attacker-controlled and must never be echoed into
        // error_description — it is redirected to a legitimate client and RFC 6749 §4.1.2.1
        // restricts the value's character set.
        foreach (var (_, values) in context.Parameters)
        {
            if (values.Count > 1)
                return InvalidRequest("A request parameter is duplicated.");
        }

        return null;
    }

    private static Problem? RequestObjectIsRefused(RequestContext context) =>
        context.Parameters.ContainsKey("request")
            ? new Problem(AuthorizeRequestErrors.RequestNotSupported, "The request parameter is not supported.")
            : null;

    private static Problem? RequestUriIsRefused(RequestContext context) =>
        context.Parameters.ContainsKey("request_uri")
            ? new Problem(AuthorizeRequestErrors.RequestUriNotSupported, "The request_uri parameter is not supported.")
            : null;

    private static Problem? ResponseTypeIsPresent(RequestContext context) =>
        string.IsNullOrEmpty(context.Single("response_type"))
            ? InvalidRequest("The response_type parameter is required.")
            : null;

    private static Problem? ResponseTypeIsCode(RequestContext context) =>
        string.Equals(context.Single("response_type"), "code", StringComparison.Ordinal)
            ? null
            : new Problem(AuthorizeRequestErrors.UnsupportedResponseType, "Only the code response type is supported.");

    private static Problem? ClientMayUseTheCodeFlow(RequestContext context) =>
        context.Client.AllowedResponseTypes.Contains(ResponseType.Code)
        && context.Client.AllowedGrantTypes.Contains(GrantType.AuthorizationCode)
            ? null
            : Unauthorized("The client may not use the authorization code flow.");

    private static Problem? ResponseModeIsQueryWhenPresent(RequestContext context)
    {
        var responseMode = context.Single("response_mode");

        return responseMode is not null && !string.Equals(responseMode, "query", StringComparison.Ordinal)
            ? InvalidRequest("Only the query response mode is supported.")
            : null;
    }

    /// <remarks>
    /// Checked on the <em>effective</em> mode, which is always query in v1, whether or not the
    /// parameter was sent — otherwise a client registered without query silently receives its
    /// code in the query string by simply omitting <c>response_mode</c>.
    /// </remarks>
    private static Problem? ClientMayUseTheQueryResponseMode(RequestContext context) =>
        context.Client.AllowedResponseModes.Contains(ResponseMode.Query)
            ? null
            : Unauthorized("The client may not use the query response mode.");

    private static Problem? ScopeIsPresent(RequestContext context)
    {
        var scope = context.Single("scope");
        if (string.IsNullOrEmpty(scope))
            return new Problem(AuthorizeRequestErrors.InvalidScope, "The scope parameter is required.");

        // Silent narrowing per RFC 6749 §3.3; the granted set is reported back via the token
        // response's scope parameter rather than as an error.
        context.EffectiveScopes.AddRange(
            scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Where(s => context.Client.AllowedScopes.Contains(s, StringComparer.Ordinal))
                .Distinct(StringComparer.Ordinal));

        return null;
    }

    private static Problem? EffectiveScopeIncludesOpenId(RequestContext context) =>
        context.EffectiveScopes.Contains("openid", StringComparer.Ordinal)
            ? null
            : new Problem(AuthorizeRequestErrors.InvalidScope, "The openid scope is required.");

    private static Problem? NonceIsPresent(RequestContext context) =>
        string.IsNullOrEmpty(context.Single("nonce"))
            ? InvalidRequest("The nonce parameter is required.")
            : null;

    private static Problem? CodeChallengeIsPresent(RequestContext context) =>
        string.IsNullOrEmpty(context.Single("code_challenge"))
            ? InvalidRequest("The code_challenge parameter is required.")
            : null;

    private static Problem? CodeChallengeIsWellFormed(RequestContext context) =>
        CodeChallengePattern().IsMatch(context.Single("code_challenge")!)
            ? null
            : InvalidRequest("The code_challenge parameter is malformed.");

    private static Problem? CodeChallengeMethodIsS256(RequestContext context)
    {
        var method = context.Single("code_challenge_method");

        if (string.IsNullOrEmpty(method))
            return InvalidRequest("The code_challenge_method parameter is required.");

        return string.Equals(method, "S256", StringComparison.Ordinal)
            ? null
            : InvalidRequest("Only the S256 code challenge method is supported.");
    }

    /// <remarks>
    /// Unrecognised values are ignored per OIDC Core §3.1.2.1. Behavioural handling of the
    /// recognised ones belongs to the interaction stage, not to validation; only syntax and the
    /// none-exclusivity rule are enforced here.
    /// </remarks>
    private static Problem? PromptValuesAreCoherent(RequestContext context)
    {
        var prompt = context.Single("prompt");
        if (string.IsNullOrEmpty(prompt))
            return null;

        foreach (var value in prompt.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (TryParsePrompt(value, out var parsed))
                context.Prompts.Add(parsed);
        }

        return context.Prompts.Contains(PromptValue.None) && context.Prompts.Count > 1
            ? InvalidRequest("The prompt value none cannot be combined with other values.")
            : null;
    }

    private static Problem? PromptValuesArePermittedForTheClient(RequestContext context)
    {
        var allowed = context.Client.AllowedPromptValues;

        return allowed.Count > 0 && !context.Prompts.IsSubsetOf(allowed)
            ? InvalidRequest("The prompt parameter requests a value the client may not use.")
            : null;
    }

    private static Problem? MaxAgeIsWellFormed(RequestContext context)
    {
        var raw = context.Single("max_age");
        if (string.IsNullOrEmpty(raw))
            return null;

        if (!long.TryParse(raw, out var seconds))
            return InvalidRequest("The max_age parameter is malformed.");

        // Capped at int.MaxValue seconds (~68 years): larger than any real max_age, and well below
        // the point where TimeSpan.FromSeconds would overflow and throw out of the endpoint.
        if (seconds is < 0 or > int.MaxValue)
            return InvalidRequest("The max_age parameter is malformed.");

        context.MaxAge = TimeSpan.FromSeconds(seconds);
        return null;
    }

    // ---- Helpers ----

    private static ValidatedAuthorizeRequest Build(RequestContext context, string redirectUri, string? state) =>
        new()
        {
            Client = context.Client,
            RedirectUri = redirectUri,
            Scopes = context.EffectiveScopes,
            State = state,
            Nonce = context.Single("nonce")!,
            CodeChallenge = context.Single("code_challenge")!,
            CodeChallengeMethod = CodeChallengeMethod.S256,
            Prompts = context.Prompts,
            MaxAge = context.MaxAge,
        };

    private static bool TryParsePrompt(string value, out PromptValue parsed)
    {
        (var recognised, parsed) = value switch
        {
            "none" => (true, PromptValue.None),
            "login" => (true, PromptValue.Login),
            "consent" => (true, PromptValue.Consent),
            "select_account" => (true, PromptValue.SelectAccount),
            _ => (false, default),
        };

        return recognised;
    }

    private static Problem InvalidRequest(string description) =>
        new(AuthorizeRequestErrors.InvalidRequest, description);

    private static Problem Unauthorized(string description) =>
        new(AuthorizeRequestErrors.UnauthorizedClient, description);

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

    /// <summary>A phase-2 validation failure: the OAuth error code and its generic description.</summary>
    private sealed record Problem(string Error, string Description);

    /// <summary>The authenticated client and the redirect URI that is safe to send it.</summary>
    private sealed record RedirectTarget(IClientRegistration Client, string RedirectUri);

    /// <summary>
    /// The request under evaluation, plus the values rules parse out of it as they run. Rules
    /// later in <see cref="Phase2Rules"/> may read what earlier ones stored here.
    /// </summary>
    private sealed class RequestContext(
        IReadOnlyDictionary<string, IReadOnlyList<string?>> parameters,
        IClientRegistration client)
    {
        public IReadOnlyDictionary<string, IReadOnlyList<string?>> Parameters => parameters;

        public IClientRegistration Client => client;

        public List<string> EffectiveScopes { get; } = [];

        public HashSet<PromptValue> Prompts { get; } = [];

        public TimeSpan? MaxAge { get; set; }

        /// <summary>The single value of <paramref name="name"/>, or <see langword="null"/>.</summary>
        public string? Single(string name) => TryGetSingle(parameters, name, out var value) ? value : null;
    }
}
