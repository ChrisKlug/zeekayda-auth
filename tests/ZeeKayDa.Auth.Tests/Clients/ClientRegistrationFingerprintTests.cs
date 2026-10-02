using FluentAssertions;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Clients;

public class ClientRegistrationFingerprintTests
{
    /// <summary>
    /// The guard that makes the fingerprint's coverage rule enforceable rather than advisory.
    /// A member added to <see cref="IClientWithCredentials"/> or <see cref="IClient"/> and
    /// not added to <c>ClientRegistrationFingerprint.Compute</c> can be changed without
    /// invalidating a cached validation verdict — so this test fails the build until both are
    /// updated together. If you are here because it failed: add the member to the fingerprint,
    /// then add its name below.
    /// </summary>
    [Fact]
    public void Fingerprint_covers_every_IClientRegistration_member()
    {
        string[] covered =
        [
            nameof(IClient.ClientId),
            nameof(IClient.IsPublic),
            nameof(IClient.EnableZkdErrorCodes),
            nameof(IClient.DisplayName),
            nameof(IClient.InitiateLoginUri),
            nameof(IClient.RequireConsent),
            nameof(IClient.SkipLogoutConfirmation),
            nameof(IClient.RequirePkce),
            nameof(IClient.RedirectUris),
            nameof(IClient.PostLogoutRedirectUris),
            nameof(IClient.AllowedScopes),
            nameof(IClient.AllowedTokenEndpointAuthMethods),
            nameof(IClient.AllowedGrantTypes),
            nameof(IClient.AllowedResponseTypes),
            nameof(IClient.AllowedResponseModes),
            nameof(IClient.AllowedPromptValues),
            nameof(IClient.AllowedSigningAlgorithms),
            nameof(IClient.AccessTokenLifetime),
            nameof(IClient.IdTokenLifetime),
            nameof(IClient.AdditionalIdTokenClaims),
            nameof(IClient.AdditionalUserInfoClaims),
            nameof(IClient.AdditionalAccessTokenClaims),
            nameof(IClientWithCredentials.Secrets),
        ];

        // Type.GetProperties() on an interface does not return inherited members, so the whole
        // implemented-interface set is walked. Naming the interfaces by hand would let a member
        // on a newly inserted base interface pass this guard while the fingerprint missed it.
        var declared = typeof(IClientWithCredentials).GetInterfaces()
            .Append(typeof(IClientWithCredentials))
            .SelectMany(t => t.GetProperties())
            .Select(p => p.Name)
            .Distinct(StringComparer.Ordinal);

        declared.Should().BeEquivalentTo(covered);

        // Naming a member in `covered` is enough to pass the check above, which would let a
        // member be listed without Compute ever reading it. The mutation theory is what proves
        // the fingerprint actually changes, so every covered member must appear there too.
        // Secrets is exercised by its own dedicated tests rather than the theory.
        MemberMutations().Keys
            .Should().BeEquivalentTo(covered.Except([nameof(IClientWithCredentials.Secrets)]));
    }

    [Fact]
    public void A_value_containing_the_field_separator_cannot_forge_another_registration()
    {
        // Values reach the fingerprint straight from the store, before validation, so a
        // delimiter-only encoding would let {"a","b"} and {"a\u001Fb"} serialize identically —
        // and a collision means an invalid registration inheriting a valid one's verdict.
        var twoScopes = NewClient() with
        {
            AllowedScopes = new HashSet<string>(StringComparer.Ordinal) { "openid", "a", "b" },
        };
        var oneJoinedScope = NewClient() with
        {
            AllowedScopes = new HashSet<string>(StringComparer.Ordinal) { "openid", "a\u001Fb" },
        };

        ClientRegistrationFingerprint.Compute(twoScopes)
            .Should().NotBe(ClientRegistrationFingerprint.Compute(oneJoinedScope));
    }

    [Fact]
    public void Equal_content_on_different_instances_produces_the_same_fingerprint()
    {
        // The property that removes the per-request PBKDF2 for a store handing out fresh
        // instances (an EF Core repository, for example).
        ClientRegistrationFingerprint.Compute(NewClient())
            .Should().Be(ClientRegistrationFingerprint.Compute(NewClient()));
    }

    [Fact]
    public void Set_ordering_does_not_change_the_fingerprint()
    {
        var forwards = NewClient() with
        {
            AllowedScopes = new HashSet<string>(StringComparer.Ordinal) { "openid", "profile", "email" },
        };
        var backwards = NewClient() with
        {
            AllowedScopes = new HashSet<string>(StringComparer.Ordinal) { "email", "profile", "openid" },
        };

        ClientRegistrationFingerprint.Compute(forwards)
            .Should().Be(ClientRegistrationFingerprint.Compute(backwards));
    }

    private static Dictionary<string, Client> MemberMutations() => new(StringComparer.Ordinal)
    {
        ["ClientId"] = NewClient() with { ClientId = "other-client" },
        ["IsPublic"] = NewClient() with { IsPublic = false },
        ["EnableZkdErrorCodes"] = NewClient() with { EnableZkdErrorCodes = true },
        ["DisplayName"] = NewClient() with { DisplayName = "Other App" },
        ["InitiateLoginUri"] = NewClient() with { InitiateLoginUri = "https://app.example.com/start" },
        ["RequireConsent"] = NewClient() with { RequireConsent = false },
        ["SkipLogoutConfirmation"] = NewClient() with { SkipLogoutConfirmation = true },
        ["RequirePkce"] = NewClient() with { RequirePkce = false },
        ["RedirectUris"] = NewClient() with { RedirectUris = new HashSet<string>(StringComparer.Ordinal) { "https://app.example.com/other" } },
        ["PostLogoutRedirectUris"] = NewClient() with { PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal) { "https://app.example.com/bye" } },
        ["AllowedScopes"] = NewClient() with { AllowedScopes = new HashSet<string>(StringComparer.Ordinal) { "openid", "admin" } },
        ["AllowedTokenEndpointAuthMethods"] = NewClient() with { AllowedTokenEndpointAuthMethods = new HashSet<string>(StringComparer.Ordinal) { TokenEndpointAuthMethods.ClientSecretBasic } },
        ["AllowedGrantTypes"] = NewClient() with { AllowedGrantTypes = new HashSet<GrantType> { GrantType.RefreshToken } },
        ["AllowedResponseTypes"] = NewClient() with { AllowedResponseTypes = new HashSet<ResponseType>() },
        ["AllowedResponseModes"] = NewClient() with { AllowedResponseModes = new HashSet<ResponseMode>() },
        ["AllowedPromptValues"] = NewClient() with { AllowedPromptValues = new HashSet<PromptValue> { PromptValue.Login } },
        ["AllowedSigningAlgorithms"] = NewClient() with { AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.RS256 } },
        ["AccessTokenLifetime"] = NewClient() with { AccessTokenLifetime = TimeSpan.FromMinutes(10) },
        ["IdTokenLifetime"] = NewClient() with { IdTokenLifetime = TimeSpan.FromMinutes(1) },
        ["AdditionalIdTokenClaims"] = NewClient() with { AdditionalIdTokenClaims = new HashSet<string>(["tenant"], StringComparer.Ordinal) },
        ["AdditionalUserInfoClaims"] = NewClient() with { AdditionalUserInfoClaims = new HashSet<string>(["tenant"], StringComparer.Ordinal) },
        ["AdditionalAccessTokenClaims"] = NewClient() with { AdditionalAccessTokenClaims = new HashSet<string>(["tenant"], StringComparer.Ordinal) },
    };

    public static TheoryData<string, Client> MutatedRegistrations()
    {
        var data = new TheoryData<string, Client>();
        foreach (var (member, registration) in MemberMutations())
            data.Add(member, registration);

        return data;
    }

    [Theory]
    [MemberData(nameof(MutatedRegistrations))]
    public void Changing_any_covered_member_changes_the_fingerprint(string member, Client mutated)
    {
        // Given a registration that differs only in {member}, the fingerprint must differ —
        // otherwise a stale verdict would keep serving a registration validation now rejects.
        ClientRegistrationFingerprint.Compute(mutated)
            .Should().NotBe(ClientRegistrationFingerprint.Compute(NewClient()), $"{member} is covered");
    }

    [Fact]
    public void Null_and_empty_AllowedSigningAlgorithms_are_distinguished()
    {
        // Null means "inherit the server's advertised set"; empty means "none permitted". They
        // validate differently, so they must not share a verdict.
        var nullAlgs = NewClient() with { AllowedSigningAlgorithms = null };
        var emptyAlgs = NewClient() with { AllowedSigningAlgorithms = new HashSet<SigningAlgorithm>() };

        ClientRegistrationFingerprint.Compute(nullAlgs)
            .Should().NotBe(ClientRegistrationFingerprint.Compute(emptyAlgs));
    }

    [Fact]
    public void Changing_a_stored_secret_changes_the_fingerprint()
    {
        var original = Confidential(hash: [1, 2, 3]);
        var rotated = Confidential(hash: [4, 5, 6]);

        ClientRegistrationFingerprint.Compute(rotated)
            .Should().NotBe(ClientRegistrationFingerprint.Compute(original),
                "a rotated secret must not inherit the previous verdict's empty-secret probe result");
    }

    [Fact]
    public void Equal_stored_secrets_on_different_instances_produce_the_same_fingerprint()
    {
        ClientRegistrationFingerprint.Compute(Confidential(hash: [1, 2, 3]))
            .Should().Be(ClientRegistrationFingerprint.Compute(Confidential(hash: [1, 2, 3])));
    }

    // ── Fixture ───────────────────────────────────────────────────────────────────────────────

    private static Client NewClient() =>
        Client.CreatePublic(
            "client-1",
            redirectUris: ["https://app.example.com/callback"],
            postLogoutRedirectUris: [],
            allowedScopes: ["openid", "profile"]);

    private static Client Confidential(byte[] hash) => NewClient() with
    {
        IsPublic = false,
        Secrets = [Pbkdf2ClientSecretHasher.Format(600_000, new byte[16], hash)],
    };
}
