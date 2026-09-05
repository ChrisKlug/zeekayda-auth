using FluentAssertions;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Clients;

public class ClientRegistrationFingerprintTests
{
    /// <summary>
    /// The guard that makes the fingerprint's coverage rule enforceable rather than advisory.
    /// A member added to <see cref="IClientRegistration"/> or <see cref="IClientMetadata"/> and
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
            nameof(IClientMetadata.ClientId),
            nameof(IClientMetadata.IsPublic),
            nameof(IClientMetadata.EnableZkdErrorCodes),
            nameof(IClientMetadata.DisplayName),
            nameof(IClientMetadata.RequireConsent),
            nameof(IClientMetadata.RedirectUris),
            nameof(IClientMetadata.PostLogoutRedirectUris),
            nameof(IClientMetadata.AllowedScopes),
            nameof(IClientMetadata.AllowedTokenEndpointAuthMethods),
            nameof(IClientMetadata.AllowedGrantTypes),
            nameof(IClientMetadata.AllowedResponseTypes),
            nameof(IClientMetadata.AllowedResponseModes),
            nameof(IClientMetadata.AllowedPromptValues),
            nameof(IClientMetadata.AllowedSigningAlgorithms),
            nameof(IClientRegistration.Credentials),
        ];

        // Type.GetProperties() on an interface does not return inherited members, so the whole
        // implemented-interface set is walked. Naming the interfaces by hand would let a member
        // on a newly inserted base interface pass this guard while the fingerprint missed it.
        var declared = typeof(IClientRegistration).GetInterfaces()
            .Append(typeof(IClientRegistration))
            .SelectMany(t => t.GetProperties())
            .Select(p => p.Name)
            .Distinct(StringComparer.Ordinal);

        declared.Should().BeEquivalentTo(covered);

        // Naming a member in `covered` is enough to pass the check above, which would let a
        // member be listed without Compute ever reading it. The mutation theory is what proves
        // the fingerprint actually changes, so every covered member must appear there too.
        // Credentials is exercised by its own dedicated tests rather than the theory.
        MemberMutations().Keys
            .Should().BeEquivalentTo(covered.Except([nameof(IClientRegistration.Credentials)]));
    }

    [Fact]
    public void A_value_containing_the_field_separator_cannot_forge_another_registration()
    {
        // Values reach the fingerprint straight from the store, before validation, so a
        // delimiter-only encoding would let {"a","b"} and {"a\u001Fb"} serialize identically —
        // and a collision means an invalid registration inheriting a valid one's verdict.
        var twoScopes = Client() with
        {
            AllowedScopes = new HashSet<string>(StringComparer.Ordinal) { "openid", "a", "b" },
        };
        var oneJoinedScope = Client() with
        {
            AllowedScopes = new HashSet<string>(StringComparer.Ordinal) { "openid", "a\u001Fb" },
        };

        ClientRegistrationFingerprint.Compute(twoScopes).Value
            .Should().NotBe(ClientRegistrationFingerprint.Compute(oneJoinedScope).Value);
    }

    [Fact]
    public void Equal_content_on_different_instances_produces_the_same_fingerprint()
    {
        // The property that removes the per-request PBKDF2 for a store handing out fresh
        // instances (an EF Core repository, for example).
        ClientRegistrationFingerprint.Compute(Client()).Value
            .Should().Be(ClientRegistrationFingerprint.Compute(Client()).Value);
    }

    [Fact]
    public void Set_ordering_does_not_change_the_fingerprint()
    {
        var forwards = Client() with
        {
            AllowedScopes = new HashSet<string>(StringComparer.Ordinal) { "openid", "profile", "email" },
        };
        var backwards = Client() with
        {
            AllowedScopes = new HashSet<string>(StringComparer.Ordinal) { "email", "profile", "openid" },
        };

        ClientRegistrationFingerprint.Compute(forwards).Value
            .Should().Be(ClientRegistrationFingerprint.Compute(backwards).Value);
    }

    private static Dictionary<string, ClientRegistration> MemberMutations() => new(StringComparer.Ordinal)
    {
        ["ClientId"] = Client() with { ClientId = "other-client" },
        ["IsPublic"] = Client() with { IsPublic = false },
        ["EnableZkdErrorCodes"] = Client() with { EnableZkdErrorCodes = true },
        ["DisplayName"] = Client() with { DisplayName = "Other App" },
        ["RequireConsent"] = Client() with { RequireConsent = false },
        ["RedirectUris"] = Client() with { RedirectUris = new HashSet<string>(StringComparer.Ordinal) { "https://app.example.com/other" } },
        ["PostLogoutRedirectUris"] = Client() with { PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal) { "https://app.example.com/bye" } },
        ["AllowedScopes"] = Client() with { AllowedScopes = new HashSet<string>(StringComparer.Ordinal) { "openid", "admin" } },
        ["AllowedTokenEndpointAuthMethods"] = Client() with { AllowedTokenEndpointAuthMethods = new HashSet<string>(StringComparer.Ordinal) { TokenEndpointAuthMethods.ClientSecretBasic } },
        ["AllowedGrantTypes"] = Client() with { AllowedGrantTypes = new HashSet<GrantType> { GrantType.RefreshToken } },
        ["AllowedResponseTypes"] = Client() with { AllowedResponseTypes = new HashSet<ResponseType>() },
        ["AllowedResponseModes"] = Client() with { AllowedResponseModes = new HashSet<ResponseMode> { ResponseMode.FormPost } },
        ["AllowedPromptValues"] = Client() with { AllowedPromptValues = new HashSet<PromptValue> { PromptValue.Login } },
        ["AllowedSigningAlgorithms"] = Client() with { AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.RS256 } },
    };

    public static TheoryData<string, ClientRegistration> MutatedRegistrations()
    {
        var data = new TheoryData<string, ClientRegistration>();
        foreach (var (member, registration) in MemberMutations())
            data.Add(member, registration);

        return data;
    }

    [Theory]
    [MemberData(nameof(MutatedRegistrations))]
    public void Changing_any_covered_member_changes_the_fingerprint(string member, ClientRegistration mutated)
    {
        // Given a registration that differs only in {member}, the fingerprint must differ —
        // otherwise a stale verdict would keep serving a registration validation now rejects.
        ClientRegistrationFingerprint.Compute(mutated).Value
            .Should().NotBe(ClientRegistrationFingerprint.Compute(Client()).Value, $"{member} is covered");
    }

    [Fact]
    public void Null_and_empty_AllowedSigningAlgorithms_are_distinguished()
    {
        // Null means "inherit the server's advertised set"; empty means "none permitted". They
        // validate differently, so they must not share a verdict.
        var nullAlgs = Client() with { AllowedSigningAlgorithms = null };
        var emptyAlgs = Client() with { AllowedSigningAlgorithms = new HashSet<SigningAlgorithm>() };

        ClientRegistrationFingerprint.Compute(nullAlgs).Value
            .Should().NotBe(ClientRegistrationFingerprint.Compute(emptyAlgs).Value);
    }

    [Fact]
    public void Changing_a_stored_secret_changes_the_fingerprint()
    {
        var original = Confidential(hash: [1, 2, 3]);
        var rotated = Confidential(hash: [4, 5, 6]);

        ClientRegistrationFingerprint.Compute(rotated).Value
            .Should().NotBe(ClientRegistrationFingerprint.Compute(original).Value,
                "a rotated secret must not inherit the previous verdict's empty-secret probe result");
    }

    [Fact]
    public void Equal_stored_secrets_on_different_instances_produce_the_same_fingerprint()
    {
        ClientRegistrationFingerprint.Compute(Confidential(hash: [1, 2, 3])).Value
            .Should().Be(ClientRegistrationFingerprint.Compute(Confidential(hash: [1, 2, 3])).Value);
    }

    [Fact]
    public void A_custom_credential_type_falls_back_to_instance_identity()
    {
        // IClientCredential is a marker interface, so a custom credential exposes nothing to
        // fingerprint by content. Distinct instances must therefore produce distinct
        // fingerprints — conservative, and no worse than instance-keyed memoization.
        var first = Client() with { Credentials = [new CustomCredential()] };
        var second = Client() with { Credentials = [new CustomCredential()] };

        var firstPrint = ClientRegistrationFingerprint.Compute(first);

        firstPrint.Value.Should().NotBe(ClientRegistrationFingerprint.Compute(second).Value);
        firstPrint.IsContentAddressable.Should().BeFalse(
            "an instance-identity fingerprint must not be cached under — request volume would grow the cache");
    }

    // ── Fixture ───────────────────────────────────────────────────────────────────────────────

    private static ClientRegistration Client() =>
        ClientRegistration.CreatePublic(
            "client-1",
            redirectUris: ["https://app.example.com/callback"],
            postLogoutRedirectUris: [],
            allowedScopes: ["openid", "profile"]);

    private static ClientRegistration Confidential(byte[] hash) => Client() with
    {
        IsPublic = false,
        Credentials = [new StubPbkdf2Secret(hash)],
    };

    private sealed class StubPbkdf2Secret(byte[] hash) : IPbkdf2ClientSecret
    {
        public int Iterations => 600_000;
        public byte[] Salt => [9, 9, 9];
        public byte[] Hash => hash;
    }

    private sealed class CustomCredential : IClientCredential;
}
