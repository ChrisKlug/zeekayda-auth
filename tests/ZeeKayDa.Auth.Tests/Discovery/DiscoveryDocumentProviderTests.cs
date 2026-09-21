#pragma warning disable ZKD001 // Tests exercise the experimental IdTokenClaims / AccessTokenClaims API by design.
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Discovery;
using ZeeKayDa.Auth.Scopes;
using ZeeKayDa.Auth.Tests.Tokens;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Discovery;

public sealed class DiscoveryDocumentProviderTests
{
    private static async Task<OpenIdConfigurationDocument> GetDocumentAsync(
        AuthorizationServerOptions options,
        IScopeRepository? scopeRepository = null,
        SigningKeySet? keySet = null)
    {
        var optionsWrapper = Microsoft.Extensions.Options.Options.Create(options);
        var provider = new DiscoveryDocumentProvider(
            optionsWrapper,
            new ValidatedScopeCatalog(scopeRepository ?? new InMemoryScopeRepository(StandardScopes.All)),
            new FakeSigningKeyRing(keySet ?? TestSigningKeys.KeySet(SigningAlgorithm.RS256)));
        return await provider.GetDocumentAsync(TestContext.Current.CancellationToken);
    }

    private sealed class FakeSigningKeyRing(SigningKeySet current) : ISigningKeyRing
    {
        public SigningKeySet Current => current;

        public ValueTask<SigningOutcome> SignAsync<TState>(
            TState state,
            Func<SigningContext, TState, ReadOnlyMemory<byte>> buildSigningInput,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        ValueTask ISigningKeyRing.EnsureInitializedAsync(CancellationToken cancellationToken)
            => throw new NotSupportedException();

        SigningKeySet? ISigningKeyRing.CurrentOrNull => current;
    }

    // ── Issuer passthrough (RFC 9207 §4) ─────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDocument_returns_Issuer_exactly_as_configured()
    {
        const string issuer = "https://auth.example.com";

        var doc = await GetDocumentAsync(new AuthorizationServerOptions { Issuer = issuer });

        doc.Issuer.Should().Be(issuer);
    }

    // ── URI derivation — root issuer (no path) ────────────────────────────────────────────────────

    [Fact]
    public async Task GetDocument_derives_AuthorizationEndpoint_for_root_Issuer()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        doc.AuthorizationEndpoint.Should().Be("https://auth.example.com/connect/authorize");
    }

    [Fact]
    public async Task GetDocument_derives_TokenEndpoint_for_root_Issuer()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        doc.TokenEndpoint.Should().Be("https://auth.example.com/connect/token");
    }

    [Fact]
    public async Task GetDocument_derives_JwksUri_for_root_Issuer()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        doc.JwksUri.Should().Be("https://auth.example.com/connect/jwks");
    }

    // ── URI derivation — path-bearing issuer ─────────────────────────────────────────────────────

    [Fact]
    public async Task GetDocument_derives_AuthorizationEndpoint_under_Issuer_path_for_path_bearing_Issuer()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1",
        });

        doc.AuthorizationEndpoint.Should().Be("https://auth.example.com/tenant1/connect/authorize");
    }

    [Fact]
    public async Task GetDocument_derives_TokenEndpoint_under_Issuer_path_for_path_bearing_Issuer()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1",
        });

        doc.TokenEndpoint.Should().Be("https://auth.example.com/tenant1/connect/token");
    }

    [Fact]
    public async Task GetDocument_derives_JwksUri_under_Issuer_path_for_path_bearing_Issuer()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1",
        });

        doc.JwksUri.Should().Be("https://auth.example.com/tenant1/connect/jwks");
    }

    // ── Explicit URI overrides ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDocument_omits_AuthorizationEndpoint_when_no_supported_grant_uses_it()
    {
        // A client_credentials-only host does not serve the endpoint, so the metadata does not
        // name it (RFC 8414 §2) — not even when the host configured an explicit URI for it — and
        // nothing that describes the endpoint is advertised either: response types, response modes
        // and PKCE methods are all omitted, since OIDC Discovery §4.2 omits a zero-element claim.
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.ClientCredentials],
            AuthorizationEndpoint =
            {
                Uri = "https://auth.example.com/custom/authorize",
                CodeChallengeMethodsSupported = [CodeChallengeMethod.S256],
            },
        });

        doc.AuthorizationEndpoint.Should().BeNull();
        doc.ResponseTypesSupported.Should().BeNull();
        doc.ResponseModesSupported.Should().BeNull();
        doc.CodeChallengeMethodsSupported.Should().BeNull();
        doc.ClaimsSupported.Should().BeNull();
        doc.GrantTypesSupported.Should().Equal(GrantType.ClientCredentials);
        doc.TokenEndpoint.Should().Be("https://auth.example.com/connect/token", "the token endpoint is what such a host serves");
    }

    [Fact]
    public async Task GetDocument_uses_override_not_derived_value_when_explicit_AuthorizationEndpoint_is_configured()
    {
        const string explicitUri = "https://other.example.com/custom/authorize";

        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { Uri = explicitUri },
        });

        doc.AuthorizationEndpoint.Should().Be(explicitUri);
    }

    [Fact]
    public async Task GetDocument_uses_override_not_derived_value_when_explicit_TokenEndpoint_is_configured()
    {
        const string explicitUri = "https://other.example.com/custom/token";

        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { Uri = explicitUri },
        });

        doc.TokenEndpoint.Should().Be(explicitUri);
    }

    [Fact]
    public async Task GetDocument_uses_override_not_derived_value_when_explicit_JwksUri_is_configured()
    {
        const string explicitUri = "https://other.example.com/custom/jwks";

        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            JwksEndpoint = { Uri = explicitUri },
        });

        doc.JwksUri.Should().Be(explicitUri);
    }

    // ── Collection fields ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDocument_includes_default_collection_values_when_using_default_options()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        doc.ResponseTypesSupported.Should().ContainSingle().Which.Should().Be(ResponseType.Code);
        doc.ScopesSupported.Should().Equal(StandardScopes.All.Select(scope => scope.Name));
        doc.ResponseModesSupported.Should().ContainSingle().Which.Should().Be(ResponseMode.Query);
        doc.GrantTypesSupported.Should().ContainSingle().Which.Should().Be(GrantType.AuthorizationCode);
        doc.TokenEndpointAuthMethodsSupported.Should().ContainSingle().Which.Should().Be(TokenEndpointAuthMethods.ClientSecretBasic);
        doc.SubjectTypesSupported.Should().ContainSingle().Which.Should().Be("public");
        doc.IdTokenSigningAlgValuesSupported.Should().ContainSingle().Which.Should().Be(SigningAlgorithm.RS256);
    }

    [Fact]
    public async Task GetDocument_uses_configured_values_for_custom_collections()
    {
        var scopeRepository = new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = StandardScopes.OpenId.Name },
            new ScopeDefinition { Name = StandardScopes.Profile.Name },
        ]);

        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            Response =
            {
                TypesSupported = [ResponseType.Code],
                ModesSupported = [ResponseMode.Query],
            },
            GrantTypesSupported = [GrantType.AuthorizationCode, GrantType.RefreshToken],
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethods.ClientSecretBasic, "tls_client_auth"] },
        }, scopeRepository, TestSigningKeys.KeySet(SigningAlgorithm.RS256, SigningAlgorithm.PS256));

        doc.ResponseTypesSupported.Should().Equal(ResponseType.Code);
        doc.ScopesSupported.Should().Equal(StandardScopes.OpenId.Name, StandardScopes.Profile.Name);
        doc.ResponseModesSupported.Should().Equal(ResponseMode.Query);
        doc.GrantTypesSupported.Should().Equal(GrantType.AuthorizationCode, GrantType.RefreshToken);
        doc.TokenEndpointAuthMethodsSupported.Should().Equal(
            TokenEndpointAuthMethods.ClientSecretBasic,
            "tls_client_auth");
        doc.IdTokenSigningAlgValuesSupported.Should().Equal(SigningAlgorithm.RS256, SigningAlgorithm.PS256);
    }

    [Fact]
    public async Task GetDocument_uses_repository_scopes_for_discovery()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition
            {
                Name = StandardScopes.OpenId.Name,
                IdTokenClaims = ["sub"],
                AccessTokenClaims = ["tenant"],
            },
            new ScopeDefinition
            {
                Name = StandardScopes.Profile.Name,
                IdTokenClaims = ["name", "family_name"],
                AccessTokenClaims = ["name"],
            },
        ]);

        var doc = await GetDocumentAsync(
            new AuthorizationServerOptions
            {
                Issuer = "https://auth.example.com",
            },
            repository);

        doc.ScopesSupported.Should().Equal(StandardScopes.OpenId.Name, StandardScopes.Profile.Name);
    }

    [Fact]
    public async Task GetDocument_excludes_non_discoverable_scopes_from_ScopeRepository()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = StandardScopes.OpenId.Name },
            new ScopeDefinition
            {
                Name = "internal.admin",
                IsDiscoverable = false,
                AccessTokenClaims = ["tenant"],
            },
        ]);

        var doc = await GetDocumentAsync(
            new AuthorizationServerOptions
            {
                Issuer = "https://auth.example.com",
            },
            repository);

        doc.ScopesSupported.Should().Equal(StandardScopes.OpenId.Name);
    }

    // ── claims_supported is derived from the scopes and the ID token's own claims ───────────────

    [Fact]
    public async Task GetDocument_advertises_the_protocol_claims_the_id_token_carries()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        // OpenID Connect Discovery 1.0 §3: the claims the server may supply. A relying party
        // reading this list must not be told about a claim no grant produces, so it is exactly
        // what CodeGrantTokenPayloads.IdToken writes.
        doc.ClaimsSupported.Should().Contain(["iss", "sub", "aud", "iat", "exp", "auth_time", "at_hash", "nonce", "acr", "amr"]);
    }

    [Fact]
    public async Task GetDocument_does_not_advertise_reserved_claims_the_id_token_never_emits()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        // These are reserved so a claims provider cannot mint them, which is a different question
        // from whether the server issues them. It does not, and advertising a claim that never
        // arrives is worse for a relying party than the metadata being absent. at_hash is not in
        // this list: the issuer does write it, so it is advertised.
        doc.ClaimsSupported.Should().NotContain(["azp", "c_hash", "sid", "nbf", "jti"]);
    }

    [Fact]
    public async Task GetDocument_omits_ClaimsSupported_when_no_supported_grant_issues_an_ID_token()
    {
        var repository = new InMemoryScopeRepository(
        [
            StandardScopes.OpenId,
            new ScopeDefinition
            {
                Name = StandardScopes.Email.Name,
                IdTokenClaims = ["email"],
                UserInfoClaims = ["email", "email_verified"],
            },
        ]);

        var doc = await GetDocumentAsync(
            new AuthorizationServerOptions
            {
                Issuer = "https://auth.example.com",
                GrantTypesSupported = [GrantType.ClientCredentials],
            },
            repository);

        // Only the authorization code grant issues an ID token or answers the UserInfo endpoint,
        // so a client_credentials-only host can supply none of these claims. Discovery §3 asks for
        // claims the server MAY supply, and advertising one nothing can produce is worse than the
        // RECOMMENDED field being absent — the same rule that omits the endpoints themselves.
        doc.ClaimsSupported.Should().BeNull();
    }

    [Fact]
    public async Task GetDocument_advertises_the_claims_the_discoverable_scopes_unlock()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition
            {
                Name = StandardScopes.OpenId.Name,
                IdTokenClaims = ["sub"],
            },
            new ScopeDefinition
            {
                Name = StandardScopes.Email.Name,
                IdTokenClaims = ["email"],
                UserInfoClaims = ["email", "email_verified"],
            },
        ]);

        var doc = await GetDocumentAsync(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com" },
            repository);

        doc.ClaimsSupported.Should().Contain(["email", "email_verified"]);
    }

    [Fact]
    public async Task GetDocument_excludes_access_token_only_claims_from_ClaimsSupported()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition
            {
                Name = StandardScopes.OpenId.Name,
                IdTokenClaims = ["sub"],
                AccessTokenClaims = ["tenant_id"],
            },
        ]);

        var doc = await GetDocumentAsync(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com" },
            repository);

        // Discovery §3 is about the ID token and the UserInfo endpoint. An access-token claim is
        // for the resource server, and a relying party cannot ask for it here.
        doc.ClaimsSupported.Should().NotContain("tenant_id");
    }

    [Fact]
    public async Task GetDocument_excludes_claims_of_non_discoverable_scopes_from_ClaimsSupported()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = StandardScopes.OpenId.Name, IdTokenClaims = ["sub"] },
            new ScopeDefinition
            {
                Name = "internal.admin",
                IsDiscoverable = false,
                IdTokenClaims = ["internal_role"],
                UserInfoClaims = ["internal_department"],
            },
        ]);

        var doc = await GetDocumentAsync(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com" },
            repository);

        // A scope hidden from discovery hides what it unlocks too, or the claim list leaks the
        // existence of the scope that scopes_supported was asked to hide.
        doc.ClaimsSupported.Should().NotContain(["internal_role", "internal_department"]);
    }

    [Fact]
    public async Task GetDocument_refuses_a_custom_repository_returning_null_claim_lists()
    {
        // Was absorbed here, each consumer reading a null list as empty on its own.
        // ValidatedScopeCatalog refuses the repository instead, so the operator is told which
        // property to fix rather than being left with a document quietly missing claims.
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = StandardScopes.OpenId.Name, IdTokenClaims = ["sub"] },
        ]);

        var act = async () => await GetDocumentAsync(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com" },
            new NullClaimListRepository(repository));

        var thrown = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        thrown.Which.AggregatedFailures.Should().OnlyContain(f => f.Code == "scopes.claims.blank");
    }

    [Fact]
    public async Task GetDocument_refuses_a_null_or_blank_claim_name_rather_than_dropping_it()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = StandardScopes.OpenId.Name, IdTokenClaims = ["sub"] },
        ]);

        // Discovery 1.0 §3 defines claims_supported as an array of strings, so a JSON null or an
        // empty name in it is malformed metadata. Dropping it silently published a document that
        // did not match the configuration; the repository is refused instead.
        var act = async () => await GetDocumentAsync(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com" },
            new BlankClaimNameRepository(repository));

        var thrown = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        thrown.Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("scopes.claims.blank");
    }

    [Fact]
    public async Task GetDocument_lists_a_claim_two_scopes_spell_differently_once()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = StandardScopes.OpenId.Name, IdTokenClaims = ["sub"] },
            new ScopeDefinition { Name = StandardScopes.Email.Name, IdTokenClaims = ["email"] },
            new ScopeDefinition { Name = "billing", UserInfoClaims = ["Email"] },
        ]);

        var doc = await GetDocumentAsync(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com" },
            repository);

        // ClaimSelection groups claim names ignoring case, so these two scopes unlock one claim
        // and the token carries one. Advertising both would name one the relying party will never
        // see under that spelling.
        doc.ClaimsSupported.Should().ContainSingle(name => string.Equals(name, "email", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task GetDocument_lists_a_claim_two_scopes_share_once()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = StandardScopes.OpenId.Name, IdTokenClaims = ["sub"] },
            new ScopeDefinition { Name = StandardScopes.Profile.Name, IdTokenClaims = ["sub", "name"] },
        ]);

        var doc = await GetDocumentAsync(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com" },
            repository);

        // "sub" is both a protocol claim and one the scopes declare; the document is a set.
        doc.ClaimsSupported.Should().OnlyHaveUniqueItems();
    }

    // ── id_token_signing_alg_values_supported is derived from the key set ────────────────────────

    [Fact]
    public async Task GetDocument_advertises_the_signing_keys_algorithm()
    {
        var doc = await GetDocumentAsync(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com" },
            keySet: TestSigningKeys.KeySet(SigningAlgorithm.ES384));

        doc.IdTokenSigningAlgValuesSupported.Should().Equal(SigningAlgorithm.ES384);
    }

    [Fact]
    public async Task GetDocument_advertises_every_published_slots_algorithm_not_only_the_signers()
    {
        // Previous and Next are published but never sign. Their algorithms must stay advertised:
        // tokens signed under a Previous key are still live and its kid is still in the JWKS.
        var doc = await GetDocumentAsync(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com" },
            keySet: TestSigningKeys.KeySet(
                SigningAlgorithm.RS256, SigningAlgorithm.ES256, SigningAlgorithm.PS512));

        doc.IdTokenSigningAlgValuesSupported.Should().Equal(
            SigningAlgorithm.RS256, SigningAlgorithm.ES256, SigningAlgorithm.PS512);
    }

    [Fact]
    public async Task GetDocument_advertises_distinct_algorithms_ascending_by_enum_value()
    {
        // Slots configured signer-first (PS512), so the ascending order below can only come from
        // the derivation, not from the order the keys happen to be listed in.
        var doc = await GetDocumentAsync(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com" },
            keySet: TestSigningKeys.KeySet(
                SigningAlgorithm.PS512, SigningAlgorithm.ES256, SigningAlgorithm.RS256));

        doc.IdTokenSigningAlgValuesSupported.Should().Equal(
            SigningAlgorithm.RS256, SigningAlgorithm.ES256, SigningAlgorithm.PS512);
    }

    [Fact]
    public async Task GetDocument_narrows_the_advertised_set_to_the_configured_filter()
    {
        var doc = await GetDocumentAsync(
            new AuthorizationServerOptions
            {
                Issuer = "https://auth.example.com",
                IdToken = { AdvertisedSigningAlgorithms = [SigningAlgorithm.RS256] },
            },
            keySet: TestSigningKeys.KeySet(SigningAlgorithm.RS256, SigningAlgorithm.ES256));

        doc.IdTokenSigningAlgValuesSupported.Should().Equal(SigningAlgorithm.RS256);
    }

    [Fact]
    public async Task GetDocument_never_advertises_an_algorithm_the_filter_names_but_no_key_uses()
    {
        var doc = await GetDocumentAsync(
            new AuthorizationServerOptions
            {
                Issuer = "https://auth.example.com",
                IdToken =
                {
                    AdvertisedSigningAlgorithms = [SigningAlgorithm.RS256, SigningAlgorithm.ES512],
                },
            },
            keySet: TestSigningKeys.KeySet(SigningAlgorithm.RS256));

        // The filter narrows what the keys allow and can never add to it.
        doc.IdTokenSigningAlgValuesSupported.Should().Equal(SigningAlgorithm.RS256);
    }

    [Fact]
    public async Task GetDocument_advertises_the_whole_published_set_when_no_filter_is_configured()
    {
        var doc = await GetDocumentAsync(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com" },
            keySet: TestSigningKeys.KeySet(SigningAlgorithm.RS256, SigningAlgorithm.ES256));

        doc.IdTokenSigningAlgValuesSupported.Should().Equal(
            SigningAlgorithm.RS256, SigningAlgorithm.ES256);
    }

    // ── Cancellation contract ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDocumentAsync_throws_via_InMemoryScopeRepository_when_token_is_already_cancelled()
    {
        var options = Microsoft.Extensions.Options.Options.Create(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com" });
        var provider = new DiscoveryDocumentProvider(
            options,
            new ValidatedScopeCatalog(new InMemoryScopeRepository(StandardScopes.All)),
            new FakeSigningKeyRing(TestSigningKeys.KeySet(SigningAlgorithm.RS256)));

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var act = async () => await provider.GetDocumentAsync(cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task GetDocumentAsync_propagates_CancellationToken_to_ScopeRepository()
    {
        var options = Microsoft.Extensions.Options.Options.Create(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com" });
        var capturingRepository = new CapturingScopeRepository();
        var provider = new DiscoveryDocumentProvider(
            options,
            new ValidatedScopeCatalog(capturingRepository),
            new FakeSigningKeyRing(TestSigningKeys.KeySet(SigningAlgorithm.RS256)));

        using var cts = new CancellationTokenSource();

        await provider.GetDocumentAsync(cts.Token);

        capturingRepository.ObservedToken.Should().Be(cts.Token);
    }

    [Fact]
    public async Task GetDocumentAsync_surfaces_exception_when_ScopeRepository_cancels()
    {
        var options = Microsoft.Extensions.Options.Options.Create(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com" });
        var provider = new DiscoveryDocumentProvider(
            options,
            new ValidatedScopeCatalog(new ThrowingScopeRepository()),
            new FakeSigningKeyRing(TestSigningKeys.KeySet(SigningAlgorithm.RS256)));

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var act = async () => await provider.GetDocumentAsync(cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    private sealed class CapturingScopeRepository : IScopeRepository
    {
        public CancellationToken ObservedToken { get; private set; }

        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
        {
            ObservedToken = cancellationToken;
            return ValueTask.FromResult<IReadOnlyCollection<ScopeDefinition>>([StandardScopes.OpenId]);
        }
    }

    private sealed class ThrowingScopeRepository : IScopeRepository
    {
        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<IReadOnlyCollection<ScopeDefinition>>([]);
        }
    }

    // ── CodeChallengeMethodsSupported ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDocument_omits_CodeChallengeMethodsSupported_field_when_null()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { CodeChallengeMethodsSupported = null },
        });

        doc.CodeChallengeMethodsSupported.Should().BeNull();
    }

    [Fact]
    public async Task GetDocument_publishes_CodeChallengeMethodsSupported_field_when_S256_is_configured()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { CodeChallengeMethodsSupported = [CodeChallengeMethod.S256] },
        });

        doc.CodeChallengeMethodsSupported.Should().ContainSingle()
            .Which.Should().Be(CodeChallengeMethod.S256);
    }

    /// <summary>A custom repository whose scopes carry null claim lists — the type system permits it.</summary>
    private sealed class NullClaimListRepository(IScopeRepository inner) : IScopeRepository
    {
        public async ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default) =>
            [.. (await inner.GetScopesAsync(cancellationToken)).Select(scope => scope with
            {
                IdTokenClaims = null!,
                UserInfoClaims = null!,
                AccessTokenClaims = null!,
            })];
    }

    /// <summary>A custom repository that slips a null and a blank name into a claim list.</summary>
    private sealed class BlankClaimNameRepository(IScopeRepository inner) : IScopeRepository
    {
        public async ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default) =>
            [.. (await inner.GetScopesAsync(cancellationToken)).Select(scope => scope with
            {
                IdTokenClaims = [.. scope.IdTokenClaims, null!, "   "],
            })];
    }

}
