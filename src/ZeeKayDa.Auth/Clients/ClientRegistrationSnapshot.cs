using System.Collections.ObjectModel;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// An immutable copy of a registration, taken once as the store hands it over; the resolver validates and
/// serves the copy, so a store's live entity cannot change after the verdict.
/// </summary>
/// <remarks>
/// <strong>Every member of <see cref="IClientWithCredentials"/> and <see cref="IClient"/> MUST be copied
/// here</strong>; <c>ClientRegistrationSnapshotTests.Snapshot_covers_every_IClientRegistration_member</c>
/// fails otherwise. String sets are rebuilt with <see cref="StringComparer.Ordinal"/>, which makes the
/// <see cref="IClient"/> comparison invariant structural. A <see cref="ClientSecret"/> is immutable, so
/// only the list is copied.
/// </remarks>
internal sealed class ClientRegistrationSnapshot : IClientWithCredentials
{
    private ClientRegistrationSnapshot(IClientWithCredentials client)
    {
        ClientId = client.ClientId;
        IsPublic = client.IsPublic;
        EnableZkdErrorCodes = client.EnableZkdErrorCodes;
        DisplayName = client.DisplayName;
        InitiateLoginUri = client.InitiateLoginUri;
        RequireConsent = client.RequireConsent;
        SkipLogoutConfirmation = client.SkipLogoutConfirmation;
        RequirePkce = client.RequirePkce;
        RedirectUris = OrdinalCopy(client.RedirectUris);
        PostLogoutRedirectUris = OrdinalCopy(client.PostLogoutRedirectUris);
        AllowedScopes = OrdinalCopy(client.AllowedScopes);
        AllowedTokenEndpointAuthMethods = OrdinalCopy(client.AllowedTokenEndpointAuthMethods);
        AllowedGrantTypes = Copy(client.AllowedGrantTypes);
        AllowedResponseTypes = Copy(client.AllowedResponseTypes);
        AllowedResponseModes = Copy(client.AllowedResponseModes);
        AllowedPromptValues = Copy(client.AllowedPromptValues);
        AllowedSigningAlgorithms = client.AllowedSigningAlgorithms is { } algorithms
            ? Copy(algorithms)
            : null;
        AccessTokenLifetime = client.AccessTokenLifetime;
        IdTokenLifetime = client.IdTokenLifetime;
        AdditionalIdTokenClaims = OrdinalCopy(client.AdditionalIdTokenClaims);
        AdditionalUserInfoClaims = OrdinalCopy(client.AdditionalUserInfoClaims);
        AdditionalAccessTokenClaims = OrdinalCopy(client.AdditionalAccessTokenClaims);
        Secrets = new ReadOnlyCollection<ClientSecret>([.. client.Secrets]);
    }

    /// <inheritdoc/>
    public string ClientId { get; }

    /// <inheritdoc/>
    public bool IsPublic { get; }

    /// <inheritdoc/>
    public bool EnableZkdErrorCodes { get; }

    /// <inheritdoc/>
    public string? DisplayName { get; }

    /// <inheritdoc/>
    public string? InitiateLoginUri { get; }

    /// <inheritdoc/>
    public bool RequireConsent { get; }

    /// <inheritdoc/>
    public bool SkipLogoutConfirmation { get; }

    /// <inheritdoc/>
    public bool RequirePkce { get; }

    /// <inheritdoc/>
    public IReadOnlySet<string> RedirectUris { get; }

    /// <inheritdoc/>
    public IReadOnlySet<string> PostLogoutRedirectUris { get; }

    /// <inheritdoc/>
    public IReadOnlySet<string> AllowedScopes { get; }

    /// <inheritdoc/>
    public IReadOnlySet<string> AllowedTokenEndpointAuthMethods { get; }

    /// <inheritdoc/>
    public IReadOnlySet<GrantType> AllowedGrantTypes { get; }

    /// <inheritdoc/>
    public IReadOnlySet<ResponseType> AllowedResponseTypes { get; }

    /// <inheritdoc/>
    public IReadOnlySet<ResponseMode> AllowedResponseModes { get; }

    /// <inheritdoc/>
    public IReadOnlySet<PromptValue> AllowedPromptValues { get; }

    /// <inheritdoc/>
    public IReadOnlySet<SigningAlgorithm>? AllowedSigningAlgorithms { get; }

    /// <inheritdoc/>
    public TimeSpan? AccessTokenLifetime { get; }

    /// <inheritdoc/>
    public TimeSpan? IdTokenLifetime { get; }

    /// <inheritdoc/>
    public IReadOnlySet<string> AdditionalIdTokenClaims { get; }

    /// <inheritdoc/>
    public IReadOnlySet<string> AdditionalUserInfoClaims { get; }

    /// <inheritdoc/>
    public IReadOnlySet<string> AdditionalAccessTokenClaims { get; }

    /// <inheritdoc/>
    public IReadOnlyList<ClientSecret> Secrets { get; }

    /// <summary>
    /// Copies <paramref name="client"/>, reading each member exactly once, and propagates whatever a getter
    /// throws; the resolver treats that as an unknown client.
    /// </summary>
    public static ClientRegistrationSnapshot Of(IClientWithCredentials client) => new(client);

    // Wrapped, never bare: code handed this registration could otherwise downcast a HashSet and add to it.
    private static IReadOnlySet<string> OrdinalCopy(IReadOnlySet<string> values) =>
        new ReadOnlySet<string>(new HashSet<string>(values, StringComparer.Ordinal));

    private static IReadOnlySet<T> Copy<T>(IReadOnlySet<T> values) =>
        new ReadOnlySet<T>(new HashSet<T>(values));
}
