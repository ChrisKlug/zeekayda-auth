using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Scopes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// Validates authorization request parameters in two phases: failures before the redirect target
/// is authenticated render locally, later ones redirect to the client (RFC 6749 §4.1.2.1).
/// </summary>
/// <remarks>
/// Error descriptions never echo a parameter's value, and an unknown client is indistinguishable
/// from an unregistered redirect URI. Phase-2 rules run in order; a rule may read what an earlier one parsed.
/// </remarks>
internal sealed partial class AuthorizeRequestValidator(
    ValidatedClientResolver clientResolver,
    ValidatedScopeCatalog scopes,
    IdTokenHintValidator idTokenHints,
    SanitizingLogger<AuthorizeRequestValidator> logger)
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
        EffectiveScopesAreDefined,
        EffectiveScopesNameOneResource,
        ClientAdditionsNameNoScopeClaim,
        CodeChallengeIsPresentUnlessTheClientMayOmitIt,
        CodeChallengeIsWellFormed,
        CodeChallengeMethodIsS256,
        PromptValuesAreCoherent,
        PromptValuesArePermittedForTheClient,
        MaxAgeIsWellFormed,
        LoginHintIsWellFormed,
        IdTokenHintWasIssuedToTheClient,
    ];

    private readonly ValidatedScopeCatalog _scopes = scopes;

    /// <summary>Validates <paramref name="parameters"/>, a multi-map so that duplicates stay observable.</summary>
    public async ValueTask<AuthorizeRequestValidationResult> ValidateAsync(
        IReadOnlyDictionary<string, IReadOnlyList<string?>> parameters,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        var target = await AuthenticateRedirectTargetAsync(parameters, cancellationToken).ConfigureAwait(false);
        if (target is null)
            return LocalError();

        var (scopes, problem) = await LoadScopesAsync(cancellationToken).ConfigureAwait(false);
        var context = new RequestContext(parameters, target.Client, scopes, idTokenHints);
        problem ??= FirstProblem(context);

        if (problem?.OperatorDetail is { } detail)
            logger.LogError("Client {ClientId} could not be served an authorization request: {Detail}", target.Client.ClientId, detail);

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

    /// <summary>
    /// Fetches the scope definitions once for the synchronous rule table, or the
    /// <c>server_error</c> problem when the repository broke its contract.
    /// </summary>
    private async ValueTask<(IReadOnlyCollection<ScopeDefinition> Scopes, Problem? Problem)> LoadScopesAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            return (await _scopes.GetScopesAsync(cancellationToken).ConfigureAwait(false), null);
        }
        catch (ScopeContractException ex)
        {
            return ([], new Problem(
                "server_error",
                "The authorization server is misconfigured.",
                "The scope repository broke its contract: " + ex.DescribeFailures()));
        }
    }

    /// <summary>Runs <see cref="Phase2Rules"/> in order and returns the first problem.</summary>
    private static Problem? FirstProblem(RequestContext context)
    {
        // A loop, not LINQ: rules parse values onto the context as they run.
        foreach (var rule in Phase2Rules)
        {
            if (rule(context) is { } problem)
                return problem;
        }

        return null;
    }

    /// <summary>
    /// The client and its redirect target, or <see langword="null"/> when either is missing,
    /// unknown or unregistered, without saying which.
    /// </summary>
    private async ValueTask<RedirectTarget?> AuthenticateRedirectTargetAsync(
        IReadOnlyDictionary<string, IReadOnlyList<string?>> parameters,
        CancellationToken cancellationToken)
    {
        if (!TryGetSingle(parameters, "client_id", out var clientId) || string.IsNullOrEmpty(clientId))
            return null;

        var client = await clientResolver.FindClientAsync(clientId, cancellationToken).ConfigureAwait(false);
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
    /// Rejects what the canonicalizing match would wave through: a fragment, userinfo, an IPv6 zone
    /// id, or a control or whitespace character that could split the <c>Location</c> header.
    /// </summary>
    private static bool IsRedirectUriShapeAcceptable(string redirectUri)
    {
        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out var parsed))
            return false;

        return string.IsNullOrEmpty(parsed.Fragment)
            && string.IsNullOrEmpty(parsed.UserInfo)
            && !RedirectUriRules.HasIpv6ZoneId(redirectUri)
            && !ContainsControlOrWhitespace(redirectUri);
    }

    // The duplicated name is attacker-controlled, so it is not echoed into the redirect.
    private static Problem? NoDuplicatedParameters(RequestContext context) =>
        context.Parameters.Any(parameter => parameter.Value.Count > 1)
            ? InvalidRequest("A request parameter is duplicated.")
            : null;

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

    // Checked whether or not response_mode was sent: the effective mode is always query.
    private static Problem? ClientMayUseTheQueryResponseMode(RequestContext context) =>
        context.Client.AllowedResponseModes.Contains(ResponseMode.Query)
            ? null
            : Unauthorized("The client may not use the query response mode.");

    private static Problem? ScopeIsPresent(RequestContext context)
    {
        var scope = context.Single("scope");
        if (string.IsNullOrEmpty(scope))
            return new Problem(AuthorizeRequestErrors.InvalidScope, "The scope parameter is required.");

        // Silent narrowing (RFC 6749 §3.3): the token response reports the granted set.
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

    // Covers a custom client repository, which skips the startup check that every scope is defined.
    private static Problem? EffectiveScopesAreDefined(RequestContext context)
    {
        if (!ScopeResolution.TryResolve(context.Scopes, context.EffectiveScopes, out var granted, out _))
            return new Problem(AuthorizeRequestErrors.InvalidScope, "The scope parameter names a scope this server does not define.");

        context.GrantedDefinitions = granted;
        return null;
    }

    // RFC 9068 §3. Checked before any interaction, so the user never sees a page for a request
    // that could not become a token; consent and refresh only narrow the scope.
    private static Problem? EffectiveScopesNameOneResource(RequestContext context) =>
        ScopeResolution.TryResolveAudience(context.GrantedDefinitions, out _)
            ? null
            : new Problem(AuthorizeRequestErrors.InvalidScope, "The scope parameter names scopes for more than one resource server.");

    // Checked per request: the registration validator's cached verdict cannot see the scope repository.
    private static Problem? ClientAdditionsNameNoScopeClaim(RequestContext context) =>
        ClientClaimAdditions.FindCollision(context.Client, context.Scopes) is { } collision
            ? new Problem(
                AuthorizeRequestErrors.ServerError,
                "The client's registration is not consistent with the server's scope configuration.",
                collision.Describe(context.Client.ClientId))
            : null;

    // A public client may never omit PKCE, whatever its registration says: a custom repository may
    // skip registration validation, and PKCE is all that binds its redemption to the flow's starter.
    private static Problem? CodeChallengeIsPresentUnlessTheClientMayOmitIt(RequestContext context)
    {
        // A challenge that is sent, empty included, is held to its shape by the next rule.
        var challenge = context.Single("code_challenge");
        if (challenge is not null)
        {
            context.CodeChallenge = challenge;
            return null;
        }

        return PkceRules.MayOmitChallenge(context.Client)
            ? null
            : InvalidRequest("The code_challenge parameter is required.");
    }

    private static Problem? CodeChallengeIsWellFormed(RequestContext context) =>
        context.CodeChallenge is null || CodeChallengePattern().IsMatch(context.CodeChallenge)
            ? null
            : InvalidRequest("The code_challenge parameter is malformed.");

    // A method without a challenge is a client that lost half its PKCE; refused rather than
    // handed a code its verifier would burn.
    private static Problem? CodeChallengeMethodIsS256(RequestContext context)
    {
        if (context.CodeChallenge is null)
        {
            return context.Single("code_challenge_method") is null
                ? null
                : InvalidRequest("The code_challenge_method parameter was sent without a code_challenge.");
        }

        var method = context.Single("code_challenge_method");

        if (string.IsNullOrEmpty(method))
            return InvalidRequest("The code_challenge_method parameter is required.");

        return string.Equals(method, "S256", StringComparison.Ordinal)
            ? null
            : InvalidRequest("Only the S256 code challenge method is supported.");
    }

    // Unrecognised values are ignored (OIDC Core §3.1.2.1); the interaction stage acts on the rest.
    private static Problem? PromptValuesAreCoherent(RequestContext context)
    {
        var prompt = context.Single("prompt");
        if (string.IsNullOrEmpty(prompt))
            return null;

        var values = prompt.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (CombinesNoneWithAnotherValue(values))
            return InvalidRequest("The prompt value none cannot be combined with other values.");

        context.Prompts.UnionWith(
            values
                .Select(value => TryParsePrompt(value, out var parsed) ? parsed : (PromptValue?)null)
                .Where(parsed => parsed.HasValue)
                .Select(parsed => parsed!.Value));

        return null;
    }

    // Judged on the raw values, so an unrecognised one counts as "any other value" too.
    private static bool CombinesNoneWithAnotherValue(string[] values) =>
        values.Contains("none", StringComparer.Ordinal)
        && values.Any(value => !string.Equals(value, "none", StringComparison.Ordinal));

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

        if (!long.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
            return InvalidRequest("The max_age parameter is malformed.");

        // Capped well below where TimeSpan.FromSeconds would overflow and throw.
        if (seconds is < 0 or > int.MaxValue)
            return InvalidRequest("The max_age parameter is malformed.");

        context.MaxAge = TimeSpan.FromSeconds(seconds);
        return null;
    }

    /// <summary>The most a <c>login_hint</c> may hold: generous for an email address or phone number.</summary>
    internal const int MaxLoginHintLength = 256;

    // No line breaks for a log line, no bidi override or invisible tag to make the pre-filled field
    // misleading. Checked per rune so an astral character is not split into halves that each pass.
    private static Problem? LoginHintIsWellFormed(RequestContext context) =>
        context.Single("login_hint") switch
        {
            { Length: > MaxLoginHintLength } => InvalidRequest("The login_hint parameter is too long."),
            { } hint when hint.EnumerateRunes().Any(IsRefusedInLoginHint) => InvalidRequest("The login_hint parameter is malformed."),
            _ => null,
        };

    // Lifetime is not checked: a client sends the ID token it already holds, usually expired by now.
    // Empty means omitted (RFC 6749 §3.1).
    private static Problem? IdTokenHintWasIssuedToTheClient(RequestContext context)
    {
        if (context.Single("id_token_hint") is not { Length: > 0 } idTokenHint)
            return null;

        if (context.IdTokenHints.Validate(idTokenHint, context.Client.ClientId) is not { } hint)
            return InvalidRequest("The id_token_hint parameter is not an ID token this server issued to the client.");

        context.RequiredSubject = hint.Subject;
        return null;
    }

    private static ValidatedAuthorizeRequest Build(RequestContext context, string redirectUri, string? state) =>
        new()
        {
            Client = context.Client,
            RedirectUri = redirectUri,
            Scopes = context.EffectiveScopes,
            State = state,
            Nonce = NonceOf(context),
            Pkce = context.CodeChallenge is { } challenge ? new PkceChallenge(challenge, CodeChallengeMethod.S256) : null,
            Prompts = context.Prompts,
            MaxAge = context.MaxAge,
            LoginHint = context.Single("login_hint") is { } hint && !string.IsNullOrWhiteSpace(hint) ? hint : null,
            RequiredSubject = context.RequiredSubject,
        };

    /// <summary>The request's <c>nonce</c>, or <see langword="null"/> when it carried none.</summary>
    /// <remarks>
    /// Optional for every client (OIDC Core §3.1.2.1): registering without PKCE is the operator's
    /// assurance that the client uses it (OAuth 2.1 §7.5.1.1). Empty means omitted (RFC 6749 §3.1).
    /// </remarks>
    private static string? NonceOf(RequestContext context) =>
        context.Single("nonce") is { Length: > 0 } nonce ? nonce : null;

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

    private static bool IsRefusedInLoginHint(Rune rune) =>
        Rune.GetUnicodeCategory(rune) switch
        {
            UnicodeCategory.Control or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator => true,
            UnicodeCategory.Format => rune.Value is not (ZeroWidthNonJoiner or ZeroWidthJoiner),
            _ => false,
        };

    // Internationalized email addresses in several scripts need these (RFC 5892 CONTEXTJ).
    private const int ZeroWidthNonJoiner = 0x200C;
    private const int ZeroWidthJoiner = 0x200D;

    private static bool ContainsControlOrWhitespace(string value) =>
        value.Any(c => char.IsControl(c) || char.IsWhiteSpace(c));

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

    /// <summary>A phase-2 failure, with the detail only the operator is told for a server-side fault.</summary>
    private sealed record Problem(string Error, string Description, string? OperatorDetail = null);

    /// <summary>The authenticated client and the redirect URI that is safe to send it.</summary>
    private sealed record RedirectTarget(IClient Client, string RedirectUri);

    /// <summary>The request under evaluation, plus the values rules parse out of it as they run.</summary>
    private sealed class RequestContext(
        IReadOnlyDictionary<string, IReadOnlyList<string?>> parameters,
        IClient client,
        IReadOnlyCollection<ScopeDefinition> scopes,
        IdTokenHintValidator idTokenHints)
    {
        public IReadOnlyDictionary<string, IReadOnlyList<string?>> Parameters => parameters;

        public IClient Client => client;

        /// <summary>Every scope the repository defines, fetched once for this request.</summary>
        public IReadOnlyCollection<ScopeDefinition> Scopes => scopes;

        public List<string> EffectiveScopes { get; } = [];

        /// <summary>Set by <c>EffectiveScopesAreDefined</c>: the definition of each effective scope, in order.</summary>
        public IReadOnlyList<ScopeDefinition> GrantedDefinitions { get; set; } = [];

        public HashSet<PromptValue> Prompts { get; } = [];

        public TimeSpan? MaxAge { get; set; }

        /// <summary>Set by <c>CodeChallengeIsPresentUnlessTheClientMayOmitIt</c>; <see langword="null"/> when the client omitted it and may.</summary>
        public string? CodeChallenge { get; set; }

        public IdTokenHintValidator IdTokenHints => idTokenHints;

        /// <summary>Set by <c>IdTokenHintWasIssuedToTheClient</c>: the subject a valid hint names.</summary>
        public string? RequiredSubject { get; set; }

        /// <summary>The single value of <paramref name="name"/>, or <see langword="null"/>.</summary>
        public string? Single(string name) => TryGetSingle(parameters, name, out var value) ? value : null;
    }
}
