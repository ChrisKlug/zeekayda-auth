using System.Collections.ObjectModel;
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
/// Every collection is copied <em>and</em> wrapped so that it cannot be cast back to something
/// mutable. The registration reaches host code — <c>TokenIssuanceContext.Client</c> hands it to the
/// host's own token issuer — and a bare <see cref="HashSet{T}"/> behind an
/// <see cref="IReadOnlySet{T}"/> is read-only by convention only.
/// </para>
/// <para>
/// The string sets are rebuilt with <see cref="StringComparer.Ordinal"/>, which makes
/// <see cref="IClientMetadata"/>'s string-set comparison invariant structural rather than a rule
/// every consumer has to remember: past this point the set's own comparer cannot be the wrong one,
/// because the framework chose it.
/// </para>
/// <para>
/// <strong>Every credential is copied by its own type.</strong> The list is rebuilt from each
/// credential's <see cref="IClientCredential.Snapshot"/>, so a store can neither add or remove a
/// credential behind a verdict nor edit one in place — <see cref="Pbkdf2ClientSecret"/> hands out
/// its <c>Salt</c> and <c>Hash</c> arrays, and <see cref="IPbkdf2ClientSecret"/>'s snapshot copies
/// them. Copying is the credential type's job rather than this class's, so a custom credential type
/// is treated exactly as the framework's own. <c>Snapshot</c> is called once per credential and its
/// result checked here: one that returns the store's instance or <see langword="null"/> makes the
/// registration unreadable (<c>client.credentials.not_copied</c>), which the resolver serves as an
/// unknown client. Leaving that check to the validator would mean asking the credential a second
/// time, and a credential that answered differently could pass while this copy held its instance.
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
        InitiateLoginUri = client.InitiateLoginUri;
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
        AdditionalIdTokenClaims = Copy(client.AdditionalIdTokenClaims);
        AdditionalUserInfoClaims = Copy(client.AdditionalUserInfoClaims);
        AdditionalAccessTokenClaims = Copy(client.AdditionalAccessTokenClaims);
        Credentials = new ReadOnlyCollection<IClientCredential>(
            [.. client.Credentials.Select(credential => CopyOf(ClientId, credential))]);
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

    // Every copy is wrapped, never handed over bare. An IReadOnlySet<string> whose runtime type is
    // HashSet<string> is read-only only by convention: TokenIssuanceContext.Client hands this
    // registration to the host's own ITokenIssuer, which can downcast the set and add to it. That
    // would reopen this type's whole reason for existing one layer further down. ReadOnlySet and
    // ReadOnlyCollection wrap a collection nothing else holds a reference to, so a downcast reaches
    // a type with no mutators rather than the backing store.
    private static IReadOnlySet<string> OrdinalCopy(IReadOnlySet<string> values) =>
        new ReadOnlySet<string>(new HashSet<string>(values, StringComparer.Ordinal));

    private static IReadOnlySet<T> Copy<T>(IReadOnlySet<T> values) =>
        new ReadOnlySet<T>(new HashSet<T>(values));

    private static IReadOnlyCollection<string> Copy(IReadOnlyCollection<string> values) =>
        new ReadOnlyCollection<string>([.. values]);

    // The one Snapshot() call per credential, checked on the spot. Throws rather than keeping the
    // store's instance: the resolver turns this exception into an unknown client whose log entry
    // carries the failure.
    private static IClientCredential CopyOf(string clientId, IClientCredential? credential)
    {
        if (credential is null)
            throw new UncopiedCredentialException(ClientCredentialValidator.NullCredential(clientId));

        var copy = credential.Snapshot();

        return ClientCredentialValidator.DescribeCopyProblem(credential, copy) is { } problem
            ? throw new UncopiedCredentialException(ClientCredentialValidator.NotCopied(clientId, credential, problem))
            : copy;
    }

    /// <summary>
    /// Thrown by <see cref="Of"/> for a credential it refused to keep. Only this class throws it,
    /// so its failure text is the framework's own and safe to log — unlike the message of anything a
    /// store's getter or a credential's <c>Snapshot</c> throws, a
    /// <see cref="ZeeKayDaConfigurationException"/> included.
    /// </summary>
    internal sealed class UncopiedCredentialException(ZeeKayDaConfigurationFailure failure)
        : Exception(failure.Message)
    {
        public ZeeKayDaConfigurationFailure Failure { get; } = failure;
    }
}
