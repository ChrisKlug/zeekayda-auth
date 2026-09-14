using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Default implementation of <see cref="IClientRegistrationValidator"/> that enforces all
/// client registration rules.
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
    private readonly ISigningKeyRing? _keyRing;

    /// <summary>
    /// Initializes a new instance of the <see cref="ClientRegistrationValidator"/> class.
    /// </summary>
    /// <param name="options">The authorization server options.</param>
    /// <param name="hasher">The composite hasher used to validate client secrets.</param>
    /// <param name="logger">The sanitizing logger.</param>
    /// <param name="keyRing">
    /// The signing key ring, or <see langword="null"/> when none is registered — a host that only
    /// adds the signing key health check has no ring, and the protocol endpoints refuse to start
    /// without one. Supplies the algorithms a client's <c>AllowedSigningAlgorithms</c> must be a
    /// subset of, once the ring has read its source. Deliberately has no default: omitting it
    /// silently weakens the subset check, which is not something a call site should be able to do
    /// by accident.
    /// </param>
    public ClientRegistrationValidator(
        IOptions<AuthorizationServerOptions> options,
        CompositeClientSecretHasher hasher,
        ISanitizingLogger<ClientRegistrationValidator> logger,
        ISigningKeyRing? keyRing)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(hasher);
        ArgumentNullException.ThrowIfNull(logger);

        _options = options;
        _hasher = hasher;
        _logger = logger;
        _keyRing = keyRing;
    }

    /// <inheritdoc/>
    public void Validate(IClientRegistration client)
    {
        ArgumentNullException.ThrowIfNull(client);

        var failures = new List<ZeeKayDaConfigurationFailure>();

        ValidateRedirectUriSet(client.ClientId, client.RedirectUris, "RedirectUris", failures);
        ValidateRedirectUriSet(client.ClientId, client.PostLogoutRedirectUris, "PostLogoutRedirectUris", failures);
        ValidateClientId(client, failures);
        ValidateDisplayName(client, failures);
        ValidateIsPublicTrinity(client, failures);
        ValidateAllowedTokenEndpointAuthMethods(client, failures);
        ValidateEmptySecretProbe(client, failures);
        ValidateCredentialConstraints(client, failures);
        ValidateTwoCredentialCap(client, failures);
        ValidateAllowedSigningAlgorithms(client, failures);
        ValidateTokenLifetimes(client, failures);
        ValidateAllowedScopes(client, failures);
        ValidateClaimAdditions(client, failures);
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
        foreach (var uriString in uriSet)
        {
            // localhost advisory warning (RFC 8252 §8.3): scheme-neutral — fires for any passing
            // URI whose host is 'localhost', including https://localhost, not just http loopback.
            // Suppressed when the URI broke a rule: a URI that is being rejected anyway should not
            // also generate advisory-warning noise.
            if (RedirectUriValidator.ValidateRedirectUri(clientId, uriString, propertyName, failures) &&
                RedirectUriRules.IsLocalhost(uriString))
            {
                _logger.LogWarning(
                    "Client '{ClientId}' uses 'localhost' in {PropertyName}: '{Uri}'. " +
                    "RFC 8252 §8.3 recommends using the IP literal '127.0.0.1' instead of 'localhost' " +
                    "to avoid DNS rebinding and cross-platform compatibility issues.",
                    clientId, propertyName, uriString);
            }
        }

        if (uriSet.Count > 32)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.redirect_uri.count_exceeded",
                $"Client '{clientId}' has {uriSet.Count} URIs in {propertyName}, which exceeds the maximum of 32."));
        }
    }

    private static void ValidateClientId(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        var clientId = client.ClientId;

        if (!IsValidClientId(clientId))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.client_id.invalid",
                $"Client has an invalid ClientId: '{clientId}'. " +
                "ClientId must match [A-Za-z0-9_\\-.]+, be non-empty, and be at most 200 characters."));
        }
    }

    /// <summary>Non-empty, at most 200 characters, and only <c>[A-Za-z0-9_\-.]</c>.</summary>
    private static bool IsValidClientId(string? clientId) =>
        !string.IsNullOrEmpty(clientId)
        && clientId.Length <= 200
        && ClientIdPattern.IsMatch(clientId);

    /// <summary>
    /// A display name is shown to users on the host's pages, so it is either absent or a
    /// printable, bounded string — never something a page has to defend itself against.
    /// </summary>
    private static void ValidateDisplayName(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        if (client.DisplayName is { } displayName && !IsValidDisplayName(displayName))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.display_name.invalid",
                $"Client '{client.ClientId}' has an invalid DisplayName. " +
                "DisplayName must be null or a non-blank string of at most 200 characters with no control characters."));
        }
    }

    /// <summary>Non-blank, at most 200 characters, and nothing a page would have to escape or hide.</summary>
    private static bool IsValidDisplayName(string displayName) =>
        !string.IsNullOrWhiteSpace(displayName)
        && displayName.Length <= 200
        && !displayName.Any(char.IsControl);

    private static void ValidateIsPublicTrinity(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        var hasNoCredentials = client.Credentials.Count == 0;

        var authMethodCount = client.AllowedTokenEndpointAuthMethods.Count;
        var authMethodsIsNoneOnly = authMethodCount == 1 &&
                                    TokenEndpointAuthMethodValidator.AllowsNone(client.AllowedTokenEndpointAuthMethods);

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
        var serverMethods = new HashSet<string>(
            _options.Value.TokenEndpoint.AuthMethodsSupported,
            StringComparer.Ordinal);

        TokenEndpointAuthMethodValidator.Validate(client, serverMethods, failures);
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

        var serverAlgorithms = ResolveServerAlgorithms();

        if (serverAlgorithms is null)
        {
            // Nothing to be a subset of: no ring has read its source yet (a repository validating
            // from its own constructor, before startup verification runs) and the operator has
            // stated no ceiling either. The JWT issuer enforces the set again at signing time, so
            // a mismatch still fails closed there; this window is only the earlier, clearer
            // message, and it says so rather than passing silently.
            if (_keyRing is not null)
            {
                _logger.LogWarning(
                    "Client '{ClientId}' declares AllowedSigningAlgorithms, but the signing key ring " +
                    "has not yet read its source, so the set could not be checked against the " +
                    "server's advertised algorithms. This happens when an IClientRepository is " +
                    "resolved before host startup verification runs.",
                    client.ClientId);
            }

            return;
        }

        // The key that signs today must be in the set, not only a key that is merely published:
        // with a ring that reads its source once, a client pinned to a next or previous key's
        // algorithm would otherwise pass startup and be refused on every exchange.
        if (_keyRing?.CurrentOrNull is { } keySet && !algorithms.Contains(keySet.SigningKey.Algorithm))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.signing_algorithms.excludes_signing_key",
                $"Client '{client.ClientId}' has AllowedSigningAlgorithms that exclude '{keySet.SigningKey.Algorithm}', " +
                "the algorithm of the current signing key, so no ID token could be issued to it. Add that " +
                "algorithm, or sign with a key the client allows."));
        }

        foreach (var algorithm in algorithms.Where(algorithm => !serverAlgorithms.Contains(algorithm)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.signing_algorithms.not_subset",
                $"Client '{client.ClientId}' has AllowedSigningAlgorithms entry '{algorithm}' that the " +
                $"server does not advertise. Advertised: [{string.Join(", ", serverAlgorithms)}]. The " +
                "advertised set is the configured signing keys' algorithms, narrowed by " +
                "IdToken.AdvertisedSigningAlgorithms when that filter is set — add a key for " +
                $"'{algorithm}', or remove it from this client."));
        }
    }

    private void ValidateTokenLifetimes(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        ValidateTokenLifetime(client, client.AccessTokenLifetime, nameof(IClientMetadata.AccessTokenLifetime), failures);
        ValidateTokenLifetime(client, client.IdTokenLifetime, nameof(IClientMetadata.IdTokenLifetime), failures);
    }

    /// <summary>
    /// A client override must be positive; one past the family ceiling only warns, because a
    /// custom repository may validate on resolution rather than at startup, and a warning there
    /// is still read while a failure would take the request down with it.
    /// </summary>
    private void ValidateTokenLifetime(
        IClientRegistration client,
        TimeSpan? lifetime,
        string propertyName,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        if (lifetime is not { } value)
            return;

        if (value <= TimeSpan.Zero)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.token_lifetime.not_positive",
                $"Client '{client.ClientId}' has {propertyName} set to {value}. " +
                "When set, a token lifetime must be greater than zero, or null to inherit the server default."));
            return;
        }

        if (value > _options.Value.TokenEndpoint.AbsoluteFamilyLifetime)
        {
            _logger.LogWarning(
                "Client '{ClientId}' has {PropertyName} set past TokenEndpoint.AbsoluteFamilyLifetime, " +
                "so a token issued to it would outlive the grant family that produced it.",
                client.ClientId,
                propertyName);
        }
    }

    /// <summary>
    /// The algorithms a client's <c>AllowedSigningAlgorithms</c> must be a subset of: the advertised
    /// set once the ring has read its source, the operator's filter alone before that, and
    /// <see langword="null"/> when neither exists.
    /// </summary>
    private IReadOnlyCollection<SigningAlgorithm>? ResolveServerAlgorithms()
    {
        var filter = _options.Value.IdToken.AdvertisedSigningAlgorithms;

        // CurrentOrNull rather than Current: this validator runs from repository constructors, which
        // a custom repository may drive before the ring has been initialized. Throwing there would
        // turn "the check cannot run yet" into a startup crash.
        return _keyRing?.CurrentOrNull is { } keySet
            ? AdvertisedSigningAlgorithms.Resolve(keySet, filter)
            : filter?.ToArray();
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

    private static void ValidateClaimAdditions(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        ValidateClaimAdditions(client, client.AdditionalIdTokenClaims, nameof(IClientMetadata.AdditionalIdTokenClaims), failures);
        ValidateClaimAdditions(client, client.AdditionalUserInfoClaims, nameof(IClientMetadata.AdditionalUserInfoClaims), failures);
        ValidateClaimAdditions(client, client.AdditionalAccessTokenClaims, nameof(IClientMetadata.AdditionalAccessTokenClaims), failures);
    }

    /// <summary>
    /// An addition is a claim name selection can act on: present, non-blank, and not one of the
    /// protocol names the framework writes itself, which selection would drop anyway. Whether it
    /// collides with a scope is checked per grant, against the scope repository this validator
    /// cannot see.
    /// </summary>
    private static void ValidateClaimAdditions(
        IClientRegistration client,
        IReadOnlyCollection<string>? additions,
        string propertyName,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        if (additions is null)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.claim_additions.null",
                $"Client '{client.ClientId}' has {propertyName} set to null. Use an empty collection for no additions."));
            return;
        }

        foreach (var _ in additions.Where(string.IsNullOrWhiteSpace))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.claim_additions.blank_entry",
                $"Client '{client.ClientId}' has a null, empty, or whitespace-only entry in {propertyName}. " +
                "Entries must be claim type names."));
        }

        foreach (var claim in additions.Where(claim => !string.IsNullOrWhiteSpace(claim) && Claims.ReservedClaimNames.IsReserved(claim)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.claim_additions.reserved",
                $"Client '{client.ClientId}' names '{claim}' in {propertyName}, which is a protocol claim the " +
                "framework writes from the grant. It cannot be supplied by a claims provider and is never selected."));
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
