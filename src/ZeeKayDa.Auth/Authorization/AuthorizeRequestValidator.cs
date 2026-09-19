using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Scopes;

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
        EffectiveScopesAreDefined,
        EffectiveScopeAudienceIsAResourceIndicator,
        EffectiveScopesNameOneResource,
        ClientAdditionsNameNoScopeClaim,
        CodeChallengeIsPresentUnlessTheClientMayOmitIt,
        CodeChallengeIsWellFormed,
        CodeChallengeMethodIsS256,
        PromptValuesAreCoherent,
        PromptValuesArePermittedForTheClient,
        MaxAgeIsWellFormed,
    ];

    private readonly ValidatedClientResolver _clientResolver;
    private readonly IScopeRepository _scopeRepository;
    private readonly ISanitizingLogger<AuthorizeRequestValidator> _logger;

    public AuthorizeRequestValidator(
        ValidatedClientResolver clientResolver,
        IScopeRepository scopeRepository,
        ISanitizingLogger<AuthorizeRequestValidator> logger)
    {
        ArgumentNullException.ThrowIfNull(clientResolver);
        ArgumentNullException.ThrowIfNull(scopeRepository);
        ArgumentNullException.ThrowIfNull(logger);

        _clientResolver = clientResolver;
        _scopeRepository = scopeRepository;
        _logger = logger;
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
        // The scope definitions are fetched once, here, because the rule table is synchronous:
        // one repository call per request, shared by every scope rule.
        var scopes = await _scopeRepository.GetScopesAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("The registered IScopeRepository returned null from GetScopesAsync.");
        var context = new RequestContext(parameters, target.Client, scopes);

        // An explicit loop, not LINQ: the rules have side effects (they parse values onto the
        // context), so short-circuiting must not depend on deferred execution.
        Problem? problem = null;
        foreach (var rule in Phase2Rules)
        {
            problem = rule(context);
            if (problem is not null)
                break;
        }

        // A server_error is the operator's bug, not the client's, and the client is told nothing
        // specific; the operator is told exactly what to fix.
        if (problem?.OperatorDetail is { } detail)
            _logger.LogError("Client {ClientId} could not be served an authorization request: {Detail}", target.Client.ClientId, detail);

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
            && !RedirectUriRules.HasIpv6ZoneId(redirectUri)
            && !ContainsControlOrWhitespace(redirectUri);
    }

    // ---- Phase 2 rules, evaluated in the order declared in Phase2Rules. ----

    private static Problem? NoDuplicatedParameters(RequestContext context)
    {
        // The offending parameter name is attacker-controlled and must never be echoed into
        // error_description — it is redirected to a legitimate client and RFC 6749 §4.1.2.1
        // restricts the value's character set.
        return context.Parameters.Any(parameter => parameter.Value.Count > 1)
            ? InvalidRequest("A request parameter is duplicated.")
            : null;
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

    /// <remarks>
    /// Every effective scope must have a definition: an undefined one has no audience to
    /// correlate to and no claims to unlock. The in-memory client registration checks this at
    /// startup; here it also covers a custom repository. The name is not echoed: it came from
    /// the client's allowed scopes, but the description travels in a redirect.
    /// </remarks>
    private static Problem? EffectiveScopesAreDefined(RequestContext context)
    {
        if (!ScopeResolution.TryResolve(context.Scopes, context.EffectiveScopes, out var granted, out _))
            return new Problem(AuthorizeRequestErrors.InvalidScope, "The scope parameter names a scope this server does not define.");

        context.GrantedDefinitions = granted;
        return null;
    }

    /// <remarks>
    /// RFC 9068 §3: scopes whose default resource indicators differ are refused with
    /// <c>invalid_scope</c>. Checked on the effective scope, before any interaction, so the user
    /// never sees a page for a request that could not become a token; consent and refresh only
    /// narrow the scope, so nothing later can introduce a second audience.
    /// </remarks>
    private static Problem? EffectiveScopesNameOneResource(RequestContext context) =>
        ScopeResolution.TryResolveAudience(context.GrantedDefinitions, out _)
            ? null
            : new Problem(AuthorizeRequestErrors.InvalidScope, "The scope parameter names scopes for more than one resource server.");

    /// <remarks>
    /// Startup refuses a malformed audience for every repository, so this is reachable only when
    /// a repository changed under a live server. That is the operator's fault, not a defect in
    /// the request, so it is <c>server_error</c> with the detail logged, not <c>invalid_scope</c>.
    /// Ordered before the one-resource rule so that two malformed audiences are still blamed on
    /// the configuration, not on the client for naming two resources.
    /// </remarks>
    private static Problem? EffectiveScopeAudienceIsAResourceIndicator(RequestContext context) =>
        ScopeResolution.FirstWithMalformedAudience(context.GrantedDefinitions) is { } scope
            ? new Problem(
                AuthorizeRequestErrors.ServerError,
                "The server's scope configuration is not valid for this request.",
                $"Scope '{scope.Name}' has an Audience of '{scope.Audience}', which is not an absolute URI without a fragment.")
            : null;

    /// <remarks>
    /// The registration's claim additions are checked against the whole scope set on every
    /// request, since the registration validator's cached verdict cannot see the scope
    /// repository. A collision is the operator's misconfiguration, answered as
    /// <c>server_error</c> and logged with the detail.
    /// </remarks>
    private static Problem? ClientAdditionsNameNoScopeClaim(RequestContext context) =>
        ClientClaimAdditions.FindCollision(context.Client, context.Scopes) is { } collision
            ? new Problem(
                AuthorizeRequestErrors.ServerError,
                "The client's registration is not consistent with the server's scope configuration.",
                collision.Describe(context.Client.ClientId))
            : null;

    /// <remarks>
    /// A registration that does not require PKCE is honoured only on a confidential client,
    /// whatever it says: a custom repository may skip registration validation, and a public
    /// client's PKCE is the only thing binding the redemption to the party that started the flow.
    /// </remarks>
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

    /// <remarks>
    /// A request that omitted the challenge has no method to check, but a method sent without a
    /// challenge is a client that meant to use PKCE and lost half of it, and is refused rather than
    /// handed a code its verifier would burn.
    /// </remarks>
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

        context.Prompts.UnionWith(
            prompt.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(value => TryParsePrompt(value, out var parsed) ? parsed : (PromptValue?)null)
                .Where(parsed => parsed.HasValue)
                .Select(parsed => parsed!.Value));

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
            Nonce = NonceOf(context),
            Pkce = context.CodeChallenge is { } challenge ? new PkceChallenge(challenge, CodeChallengeMethod.S256) : null,
            Prompts = context.Prompts,
            MaxAge = context.MaxAge,
        };

    /// <summary>The request's <c>nonce</c>, or <see langword="null"/> when it carried none.</summary>
    /// <remarks>
    /// Not a rule, because nothing about it can fail. The <c>nonce</c> is optional for the code
    /// flow (OIDC Core §3.1.2.1), for every client: one registered without PKCE is not asked for it
    /// either, because that registration is the operator's assurance that the client uses it (OAuth
    /// 2.1 §7.5.1.1). One sent without a value is treated as omitted (RFC 6749 §3.1).
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

    /// <summary>
    /// A phase-2 validation failure: the OAuth error code and its generic description, and for a
    /// server-side fault, the detail the operator is told and the client is not.
    /// </summary>
    private sealed record Problem(string Error, string Description, string? OperatorDetail = null);

    /// <summary>The authenticated client and the redirect URI that is safe to send it.</summary>
    private sealed record RedirectTarget(IClientRegistration Client, string RedirectUri);

    /// <summary>
    /// The request under evaluation, plus the values rules parse out of it as they run. Rules
    /// later in <see cref="Phase2Rules"/> may read what earlier ones stored here.
    /// </summary>
    private sealed class RequestContext(
        IReadOnlyDictionary<string, IReadOnlyList<string?>> parameters,
        IClientRegistration client,
        IReadOnlyCollection<ScopeDefinition> scopes)
    {
        public IReadOnlyDictionary<string, IReadOnlyList<string?>> Parameters => parameters;

        public IClientRegistration Client => client;

        /// <summary>Every scope the repository defines, fetched once for this request.</summary>
        public IReadOnlyCollection<ScopeDefinition> Scopes => scopes;

        public List<string> EffectiveScopes { get; } = [];

        /// <summary>Set by <c>EffectiveScopesAreDefined</c>: the definition of each effective scope, in order.</summary>
        public IReadOnlyList<ScopeDefinition> GrantedDefinitions { get; set; } = [];

        public HashSet<PromptValue> Prompts { get; } = [];

        public TimeSpan? MaxAge { get; set; }

        /// <summary>Set by <c>CodeChallengeIsPresentUnlessTheClientMayOmitIt</c>; <see langword="null"/> when the client omitted it and may.</summary>
        public string? CodeChallenge { get; set; }

        /// <summary>The single value of <paramref name="name"/>, or <see langword="null"/>.</summary>
        public string? Single(string name) => TryGetSingle(parameters, name, out var value) ? value : null;
    }
}
