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
/// Registered as a singleton by <c>AddZeeKayDaAuth()</c>. Areas with more than one rule or a
/// dependency of their own live in their own validators; this class holds the dependencies,
/// does all the logging, and keeps only the single-rule checks.
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
        ValidateAllowedTokenEndpointAuthMethods(client, failures);
        ClientCredentialValidator.Validate(client, _hasher, failures);
        ValidateAllowedSigningAlgorithms(client, failures);
        ValidateTokenLifetimes(client, failures);
        ValidateAllowedScopes(client, failures);
        ClaimAdditionValidator.Validate(client, failures);
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

    private void ValidateAllowedTokenEndpointAuthMethods(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        var serverMethods = new HashSet<string>(
            _options.Value.TokenEndpoint.AuthMethodsSupported,
            StringComparer.Ordinal);

        TokenEndpointAuthMethodValidator.Validate(client, serverMethods, failures);
    }

    private void ValidateAllowedSigningAlgorithms(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        var checkedAgainstServer = SigningAlgorithmValidator.Validate(
            client, _keyRing, _options.Value.IdToken.AdvertisedSigningAlgorithms, failures);

        // Say so rather than passing silently. A host with no ring at all stays quiet: the protocol
        // endpoints refuse to start without one, so there is nothing a warning here would add.
        if (!checkedAgainstServer && _keyRing is not null)
        {
            _logger.LogWarning(
                "Client '{ClientId}' declares AllowedSigningAlgorithms, but the signing key ring " +
                "has not yet read its source, so the set could not be checked against the " +
                "server's advertised algorithms. This happens when an IClientRepository is " +
                "resolved before host startup verification runs.",
                client.ClientId);
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
