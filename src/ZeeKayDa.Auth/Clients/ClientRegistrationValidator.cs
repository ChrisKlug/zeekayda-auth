using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Default implementation of <see cref="IClientRegistrationValidator"/> that enforces all
/// ADR 0007 client registration rules.
/// </summary>
/// <remarks>
/// Aggregates all violations before throwing so operators see every problem in one pass.
/// Registered as a singleton by <c>AddZeeKayDaAuth()</c>.
/// </remarks>
internal sealed class ClientRegistrationValidator : IClientRegistrationValidator
{
    private static readonly Regex ClientIdPattern =
        new(@"^[A-Za-z0-9_\-.]+$", RegexOptions.Compiled, TimeSpan.FromMilliseconds(100));

    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly CompositeClientSecretHasher _hasher;
    private readonly ISanitizingLogger<ClientRegistrationValidator> _logger;

    public ClientRegistrationValidator(
        IOptions<AuthorizationServerOptions> options,
        CompositeClientSecretHasher hasher,
        ISanitizingLogger<ClientRegistrationValidator> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(hasher);
        ArgumentNullException.ThrowIfNull(logger);

        _options = options;
        _hasher = hasher;
        _logger = logger;
    }

    /// <inheritdoc/>
    public void Validate(IClientRegistration client)
    {
        ArgumentNullException.ThrowIfNull(client);

        var failures = new List<ZeeKayDaConfigurationFailure>();

        ValidateRedirectUriSet(client.ClientId, client.RedirectUris, "RedirectUris", failures);
        ValidateRedirectUriSet(client.ClientId, client.PostLogoutRedirectUris, "PostLogoutRedirectUris", failures);
        ValidateClientId(client, failures);
        ValidateIsPublicTrinity(client, failures);
        ValidateAllowedTokenEndpointAuthMethods(client, failures);
        ValidateEmptySecretProbe(client, failures);
        ValidateCredentialConstraints(client, failures);
        ValidateTwoCredentialCap(client, failures);
        ValidateAllowedSigningAlgorithms(client, failures);
        ValidateAllowedScopes(client, failures);
        ValidateEnumSets(client, failures);

        if (failures.Count > 0)
            throw new ZeeKayDaConfigurationException([.. failures]);
    }

    private void ValidateRedirectUriSet(
        string clientId,
        IReadOnlySet<string> uriSet,
        string propertyName,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        var count = 0;

        foreach (var uriString in uriSet)
        {
            count++;

            var failuresBefore = failures.Count;

            if (!Uri.TryCreate(uriString, UriKind.Absolute, out var uri))
            {
                failures.Add(new ZeeKayDaConfigurationFailure(
                    "client.redirect_uri.invalid",
                    $"Client '{clientId}' has an invalid URI in {propertyName}: '{uriString}'. " +
                    "The value could not be parsed as an absolute URI."));
                continue;
            }

            // IPv6 zone-ID check: .NET strips zone IDs from uri.Host at parse time, so we must
            // inspect the original string. A URI with an IPv6 zone ID (e.g. [::1%25eth0]) binds
            // to a specific network interface, not the loopback stack, and must not be trusted.
            // This is scheme-neutral: an https:// URI with a zone ID is just as prohibited as an
            // http:// one, so it is checked here rather than inside the http branch of
            // IsSchemeAllowed.
            if (RedirectUriValidator.HasIpv6ZoneId(uriString))
            {
                failures.Add(new ZeeKayDaConfigurationFailure(
                    "client.redirect_uri.ipv6_zone_id",
                    $"Client '{clientId}' has a redirect URI in {propertyName} with an IPv6 zone ID: '{uriString}'. " +
                    "Zone IDs bind to a specific network interface rather than the loopback stack and are prohibited in redirect URIs."));
                // still continue to check other rules
            }

            // Fragment check
            if (uri.Fragment.Length > 0)
            {
                failures.Add(new ZeeKayDaConfigurationFailure(
                    "client.redirect_uri.fragment",
                    $"Client '{clientId}' has a redirect URI in {propertyName} with a fragment component: '{uriString}'. " +
                    "Fragment components are prohibited in redirect URIs (RFC 9700 §2.1)."));
            }

            // UserInfo check
            if (uri.UserInfo.Length > 0)
            {
                failures.Add(new ZeeKayDaConfigurationFailure(
                    "client.redirect_uri.userinfo",
                    $"Client '{clientId}' has a redirect URI in {propertyName} with a userinfo component: '{uriString}'. " +
                    "Userinfo components are prohibited in redirect URIs."));
            }

            // Path traversal check — must inspect the original string because .NET's Uri parser
            // normalises '..' and '.' away during construction (AbsolutePath will not contain them).
            if (RedirectUriValidator.HasPathTraversal(uriString))
            {
                failures.Add(new ZeeKayDaConfigurationFailure(
                    "client.redirect_uri.path_traversal",
                    $"Client '{clientId}' has a redirect URI in {propertyName} with a path traversal segment: '{uriString}'. " +
                    "Path traversal segments ('.' or '..') are prohibited in redirect URIs."));
            }

            // Scheme allowlist check
            if (!RedirectUriValidator.IsSchemeAllowed(uri))
            {
                var httpScheme = string.Equals(uri.Scheme, "http", StringComparison.OrdinalIgnoreCase);
                if (httpScheme)
                {
                    failures.Add(new ZeeKayDaConfigurationFailure(
                        "client.redirect_uri.scheme_http_non_loopback",
                        $"Client '{clientId}' has a redirect URI in {propertyName} using HTTP for a non-loopback host: '{uriString}'. " +
                        "HTTP redirect URIs are only permitted for loopback addresses (RFC 8252 §8.3)."));
                }
                else
                {
                    failures.Add(new ZeeKayDaConfigurationFailure(
                        "client.redirect_uri.scheme_not_allowed",
                        $"Client '{clientId}' has a redirect URI in {propertyName} with a disallowed scheme: '{uriString}'. " +
                        "Permitted schemes are 'https', 'http' (loopback only), and private-use schemes containing a dot."));
                }
            }

            // localhost advisory warning (RFC 8252 §8.3): scheme-neutral — fires for any passing
            // URI whose host is 'localhost', including https://localhost, not just http loopback.
            // Suppressed when the URI already accumulated other failures in this iteration: a URI
            // that is being rejected anyway should not also generate advisory-warning noise.
            if (failures.Count == failuresBefore &&
                string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning(
                    "Client '{ClientId}' uses 'localhost' in {PropertyName}: '{Uri}'. " +
                    "RFC 8252 §8.3 recommends using the IP literal '127.0.0.1' instead of 'localhost' " +
                    "to avoid DNS rebinding and cross-platform compatibility issues.",
                    clientId, propertyName, uriString);
            }
        }

        if (count > 32)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.redirect_uri.count_exceeded",
                $"Client '{clientId}' has {count} URIs in {propertyName}, which exceeds the maximum of 32."));
        }
    }

    private static void ValidateClientId(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        var clientId = client.ClientId;

        if (clientId is null || clientId.Length == 0 || clientId.Length > 200 ||
            !ClientIdPattern.IsMatch(clientId))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.client_id.invalid",
                $"Client has an invalid ClientId: '{clientId}'. " +
                "ClientId must match [A-Za-z0-9_\\-.]+, be non-empty, and be at most 200 characters."));
        }
    }

    private static void ValidateIsPublicTrinity(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        var hasNoCredentials = client.Credentials.Count == 0;

        // Enumerate with explicit ordinal comparison — do NOT trust the set's comparer
        var authMethodsIsNoneOnly = false;
        var authMethodCount = 0;
        var hasNoneMethod = false;

        foreach (var method in client.AllowedTokenEndpointAuthMethods)
        {
            authMethodCount++;
            if (string.Equals(method, TokenEndpointAuthMethods.None, StringComparison.Ordinal))
                hasNoneMethod = true;
        }

        authMethodsIsNoneOnly = authMethodCount == 1 && hasNoneMethod;

        // Check empty AllowedTokenEndpointAuthMethods for confidential clients explicitly
        if (!client.IsPublic && authMethodCount == 0)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.token_endpoint_auth_methods.empty",
                $"Client '{client.ClientId}' is confidential (IsPublic=false) but AllowedTokenEndpointAuthMethods is empty. " +
                "Confidential clients must specify at least one token endpoint authentication method."));
        }

        // Three-way consistency check
        if (client.IsPublic != hasNoCredentials || client.IsPublic != authMethodsIsNoneOnly)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.is_public.trinity_violation",
                $"Client '{client.ClientId}' has inconsistent public/confidential configuration. " +
                $"IsPublic={client.IsPublic}, Credentials.Count={client.Credentials.Count}, " +
                $"AllowedTokenEndpointAuthMethods=[{string.Join(", ", client.AllowedTokenEndpointAuthMethods)}]. " +
                "The three-way consistency rule requires: IsPublic=true ⟺ Credentials.Count=0 ⟺ AllowedTokenEndpointAuthMethods={\"none\"}."));
        }
    }

    private void ValidateAllowedTokenEndpointAuthMethods(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);

        var serverMethods = new HashSet<string>(
            _options.Value.TokenEndpoint.AuthMethodsSupported,
            StringComparer.Ordinal);

        // A confidential client must never advertise 'none' as a valid auth method: doing so would
        // allow it to be called without credentials. The trinity check only rejects a "none-only"
        // confidential client, so a mixed set like {"none","client_secret_basic"} slips past it.
        if (!client.IsPublic &&
            client.AllowedTokenEndpointAuthMethods.Any(
                m => string.Equals(m, TokenEndpointAuthMethods.None, StringComparison.Ordinal)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.token_endpoint_auth_methods.none_on_confidential",
                $"Confidential client '{client.ClientId}' has 'none' in AllowedTokenEndpointAuthMethods. " +
                "The 'none' method is only valid for public clients (RFC 6749 §2.3)."));
        }

        foreach (var method in client.AllowedTokenEndpointAuthMethods)
        {
            // Invalid entry check
            if (method is null || method.Length == 0 ||
                method != method.Trim() ||
                method.Any(char.IsControl))
            {
                failures.Add(new ZeeKayDaConfigurationFailure(
                    "client.token_endpoint_auth_methods.invalid_entry",
                    $"Client '{client.ClientId}' has an invalid entry in AllowedTokenEndpointAuthMethods: " +
                    $"'{method}'. Entries must be non-null, non-empty, have no leading/trailing whitespace, " +
                    "and contain no control characters."));
                continue;
            }

            // Duplicate check
            if (!seen.Add(method))
            {
                failures.Add(new ZeeKayDaConfigurationFailure(
                    "client.token_endpoint_auth_methods.duplicate",
                    $"Client '{client.ClientId}' has a duplicate entry in AllowedTokenEndpointAuthMethods: '{method}'."));
                continue;
            }

            // Subset check against server's supported methods
            if (!serverMethods.Contains(method))
            {
                failures.Add(new ZeeKayDaConfigurationFailure(
                    "client.token_endpoint_auth_methods.not_subset",
                    $"Client '{client.ClientId}' has AllowedTokenEndpointAuthMethods entry '{method}' that is not " +
                    $"in the server's AuthMethodsSupported: [{string.Join(", ", serverMethods)}]."));
            }
        }
    }

    private void ValidateEmptySecretProbe(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        foreach (var _ in client.Credentials
                     .OfType<IClientSecret>()
                     .Where(secret => _hasher.Verify(secret, ReadOnlySpan<char>.Empty)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.credentials.empty_secret_accepted",
                $"A credential for client '{client.ClientId}' accepts an empty presented secret. " +
                "Credentials must not accept empty secrets — this would allow unauthenticated access " +
                "to the client. Review the stored credential and the associated hasher."));
        }

        // The empty-secret probe above only catches hashers that accept empty passwords. A
        // credential whose type no registered hasher CanHandle would silently pass validation and
        // only fail at runtime as invalid_client. Reject it here so the misconfiguration is caught
        // at registration time instead.
        foreach (var secret in client.Credentials
                     .OfType<IClientSecret>()
                     .Where(secret => !_hasher.CanHandleAny(secret)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.credentials.no_hasher",
                $"Client '{client.ClientId}' has a credential of type '{secret.GetType().Name}' " +
                "for which no registered IClientSecretHasher.CanHandle returns true. " +
                "The credential can never be verified."));
        }
    }

    private void ValidateCredentialConstraints(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        foreach (var secret in client.Credentials.OfType<IClientSecret>())
            failures.AddRange(_hasher.GetRegistrationFailures(secret, client.ClientId));
    }

    private static void ValidateTwoCredentialCap(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        var secretCount = client.Credentials.OfType<IClientSecret>().Count();

        if (secretCount > CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.credentials.too_many_secrets",
                $"Client '{client.ClientId}' has {secretCount} IClientSecret credentials, which exceeds the " +
                $"maximum of {CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient}. " +
                "The two-credential cap exists to support credential rotation while preserving timing-oracle defences."));
        }
    }

    private void ValidateAllowedSigningAlgorithms(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        var algorithms = client.AllowedSigningAlgorithms;

        if (algorithms is null)
            return;

        if (algorithms.Count == 0)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.signing_algorithms.empty_when_set",
                $"Client '{client.ClientId}' has AllowedSigningAlgorithms set to a non-null empty set. " +
                "When set, AllowedSigningAlgorithms must contain at least one value, or be null to inherit the server default."));
            return;
        }

        var serverAlgorithms = _options.Value.IdToken.SigningAlgValuesSupported;

        foreach (var algorithm in algorithms.Where(algorithm => !serverAlgorithms.Contains(algorithm)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.signing_algorithms.not_subset",
                $"Client '{client.ClientId}' has AllowedSigningAlgorithms entry '{algorithm}' that is not " +
                $"in the server's IdToken.SigningAlgValuesSupported: [{string.Join(", ", serverAlgorithms)}]."));
        }
    }

    private static void ValidateAllowedScopes(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        foreach (var _ in client.AllowedScopes.Where(string.IsNullOrWhiteSpace))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.allowed_scopes.blank_entry",
                $"Client '{client.ClientId}' has a null, empty, or whitespace-only entry in AllowedScopes. " +
                "Scope entries must be non-empty non-whitespace strings."));
        }
    }

    private static void ValidateEnumSets(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        foreach (var grantType in client.AllowedGrantTypes.Where(grantType => !Enum.IsDefined(grantType)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.grant_types.undefined_value",
                $"Client '{client.ClientId}' has an undefined value '{(int)grantType}' in AllowedGrantTypes."));
        }

        foreach (var responseType in client.AllowedResponseTypes.Where(responseType => !Enum.IsDefined(responseType)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.response_types.undefined_value",
                $"Client '{client.ClientId}' has an undefined value '{(int)responseType}' in AllowedResponseTypes."));
        }

        foreach (var responseMode in client.AllowedResponseModes.Where(responseMode => !Enum.IsDefined(responseMode)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.response_modes.undefined_value",
                $"Client '{client.ClientId}' has an undefined value '{(int)responseMode}' in AllowedResponseModes."));
        }

        foreach (var promptValue in client.AllowedPromptValues.Where(promptValue => !Enum.IsDefined(promptValue)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.prompt_values.undefined_value",
                $"Client '{client.ClientId}' has an undefined value '{(int)promptValue}' in AllowedPromptValues."));
        }
    }

}
