using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// An immutable copy of an <see cref="IClientRegistration"/>, read once at the point the store
/// hands it over. <see cref="ValidatedClientResolver"/> validates the copy and serves the copy.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Every member of <see cref="IClientRegistration"/> and <see cref="IClientMetadata"/>
/// MUST be copied here.</strong> A member left reading through to the store's instance can change
/// after the verdict that blessed it, which is the whole bug this type exists to close. When adding
/// a member to either interface, add it here in the same change —
/// <c>ClientRegistrationSnapshotTests.Snapshot_covers_every_IClientRegistration_member</c> fails
/// the build if you do not.
/// </para>
/// <para>
/// A registration is an extension point, and nothing obliges a custom store to hand out a value
/// object: it may return an ORM entity whose collections are still attached to a change tracker,
/// or one instance shared across requests and edited in place. Validating a reference the
/// framework does not own validates nothing durable — the resolver would fingerprint and approve
/// one set of redirect URIs, and the authorize endpoint would then match the request against
/// whatever the set held by then. Copying at the choke point is what makes "validated" mean the
/// values the caller actually gets.
/// </para>
/// <para>
/// The string sets are rebuilt with <see cref="StringComparer.Ordinal"/>, which makes
/// <see cref="IClientMetadata"/>'s string-set comparison invariant structural rather than a rule
/// every consumer has to remember: past this point the set's own comparer cannot be the wrong one,
/// because the framework chose it.
/// </para>
/// <para>
/// <strong>Credentials are copied as a list, not as values.</strong> The list is snapshotted, so a
/// store cannot add or remove a credential behind a verdict, but the credential objects themselves
/// are shared with the store's instance. <see cref="Pbkdf2ClientSecret"/> documents that it hands
/// out its own <c>Salt</c> and <c>Hash</c> arrays and that the framework does not defensively copy
/// them; deep-copying here would contradict that decision, not extend it.
/// </para>
/// </remarks>
internal sealed class ClientRegistrationSnapshot : IClientRegistration
{
    private ClientRegistrationSnapshot(IClientRegistration client)
    {
        ClientId = client.ClientId;
        IsPublic = client.IsPublic;
        EnableZkdErrorCodes = client.EnableZkdErrorCodes;
        DisplayName = client.DisplayName;
        RequireConsent = client.RequireConsent;
        SkipLogoutConfirmation = client.SkipLogoutConfirmation;
        AllowNonceInsteadOfPkce = client.AllowNonceInsteadOfPkce;
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
        AdditionalIdTokenClaims = [.. client.AdditionalIdTokenClaims];
        AdditionalUserInfoClaims = [.. client.AdditionalUserInfoClaims];
        AdditionalAccessTokenClaims = [.. client.AdditionalAccessTokenClaims];
        Credentials = [.. client.Credentials];
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
    public bool RequireConsent { get; }

    /// <inheritdoc/>
    public bool SkipLogoutConfirmation { get; }

    /// <inheritdoc/>
    public bool AllowNonceInsteadOfPkce { get; }

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
    public IReadOnlyCollection<string> AdditionalIdTokenClaims { get; }

    /// <inheritdoc/>
    public IReadOnlyCollection<string> AdditionalUserInfoClaims { get; }

    /// <inheritdoc/>
    public IReadOnlyCollection<string> AdditionalAccessTokenClaims { get; }

    /// <inheritdoc/>
    public IReadOnlyList<IClientCredential> Credentials { get; }

    /// <summary>
    /// Copies <paramref name="client"/>. Every member is read exactly once, here, so a store that
    /// answers differently on a second read cannot answer one thing to validation and another to
    /// the protocol.
    /// </summary>
    /// <remarks>
    /// Propagates whatever a member's getter throws. The caller —
    /// <see cref="ValidatedClientResolver"/> — turns that into an unknown client, on the same terms
    /// as a registration that fails validation.
    /// </remarks>
    public static ClientRegistrationSnapshot Of(IClientRegistration client) => new(client);

    private static IReadOnlySet<string> OrdinalCopy(IReadOnlySet<string> values) =>
        new HashSet<string>(values, StringComparer.Ordinal);

    private static IReadOnlySet<T> Copy<T>(IReadOnlySet<T> values) => new HashSet<T>(values);
}
