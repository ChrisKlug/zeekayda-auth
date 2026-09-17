using System.Collections;
using System.Reflection;
using FluentAssertions;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Clients;

public class ClientRegistrationSnapshotTests
{
    /// <summary>
    /// The guard that makes the snapshot's coverage rule enforceable rather than advisory. A
    /// member added to <see cref="IClientRegistration"/> or <see cref="IClientMetadata"/> and not
    /// copied by the snapshot keeps reading through to the store's instance, which is the bug the
    /// snapshot exists to close — so this test fails the build until both are updated together.
    /// If you are here because it failed: copy the member in the snapshot, then add a mutation for
    /// it below.
    /// </summary>
    [Fact]
    public void Snapshot_covers_every_IClientRegistration_member()
    {
        // Type.GetProperties() on an interface does not return inherited members, so the whole
        // implemented-interface set is walked — the same reason the fingerprint's guard does it.
        DeclaredProperties().Select(p => p.Name).Should().BeEquivalentTo(MemberMutations().Keys);
    }

    /// <summary>
    /// The guard that catches a member the snapshot forgot to copy. Such a member is not a compile
    /// error — <see cref="IClientMetadata"/>'s newer members are default interface implementations,
    /// so an uncopied one silently answers the interface default instead of the store's value.
    /// Fingerprint equality is the check because the fingerprint covers every member and has its
    /// own guard saying so, and the fixture leaves no member at a default an omission could match.
    /// </summary>
    [Fact]
    public void A_snapshot_carries_every_value_of_the_registration_it_copied()
    {
        var registration = FullyPopulated();

        ClientRegistrationFingerprint.Compute(ClientRegistrationSnapshot.Of(registration)).Value
            .Should().Be(ClientRegistrationFingerprint.Compute(registration).Value);
    }

    /// <summary>
    /// Keeps the test above honest. A member the fixture left at <see langword="false"/>,
    /// <see langword="null"/> or empty would fingerprint identically whether it was copied or
    /// forgotten, so the omission would pass unnoticed.
    /// </summary>
    [Fact]
    public void The_fixture_leaves_no_member_at_a_value_an_omission_could_match()
    {
        var registration = FullyPopulated();
        var members = DeclaredProperties().Select(p => (p.Name, Value: p.GetValue(registration)));

        foreach (var (name, value) in members)
        {
            var because = $"{name} must differ from what an uncopied member would hold";

            value.Should().NotBeNull(because);
            (value as bool?)?.Should().BeTrue(because);
            // A string matches too, which is what we want: an empty ClientId or DisplayName is
            // exactly the value an uncopied one would hold.
            (value as IEnumerable)?.Cast<object>().Should().NotBeEmpty(because);
        }
    }

    [Theory]
    [MemberData(nameof(MutatedMembers))]
    public void Changing_a_member_after_the_snapshot_leaves_the_snapshot_alone(
        string member,
        Action<MutableRegistration> mutate)
    {
        var registration = new MutableRegistration();
        var snapshot = ClientRegistrationSnapshot.Of(registration);
        var before = ClientRegistrationFingerprint.Compute(snapshot).Value;

        mutate(registration);

        // Guards the theory against a mutation that changes nothing: unless the live registration
        // now fingerprints differently, the assertion below would pass vacuously.
        ClientRegistrationFingerprint.Compute(registration).Value
            .Should().NotBe(before, $"the {member} mutation must be a real change");
        ClientRegistrationFingerprint.Compute(snapshot).Value
            .Should().Be(before, $"{member} is copied, not read through to the store's instance");
    }

    [Fact]
    public void Editing_the_redirect_set_in_place_leaves_the_snapshot_alone()
    {
        // The mutation the theory above cannot make: the store keeps the same collection instance
        // and edits its contents, so a snapshot that copied only the reference would still change.
        var uris = new HashSet<string>(StringComparer.Ordinal) { "https://app.example.com/callback" };
        var snapshot = ClientRegistrationSnapshot.Of(new MutableRegistration { RedirectUris = uris });

        uris.Add("https://attacker.example.com/callback");

        snapshot.RedirectUris.Should().NotContain("https://attacker.example.com/callback");
    }

    [Fact]
    public void Adding_a_credential_after_the_snapshot_leaves_the_snapshot_alone()
    {
        var credentials = new List<IClientCredential>();
        var snapshot = ClientRegistrationSnapshot.Of(new MutableRegistration { Credentials = credentials });

        credentials.Add(new StubPbkdf2Secret());

        snapshot.Credentials.Should().BeEmpty(
            "a store must not be able to hand a client a credential behind the verdict that called it public");
    }

    [Theory]
    [MemberData(nameof(CredentialEdits))]
    public void Editing_a_credential_in_place_after_the_snapshot_leaves_the_snapshot_alone(
        string edit,
        Action<MutablePbkdf2Secret> apply)
    {
        // Copying the credential list is not enough: a store entity's salt and hash are arrays it
        // still holds, and writing into them would change the secret the authenticator checks after
        // validation approved the old one.
        var credential = new MutablePbkdf2Secret();
        var snapshot = ClientRegistrationSnapshot.Of(new MutableRegistration { Credentials = [credential] });
        var before = ClientRegistrationFingerprint.Compute(snapshot).Value;

        apply(credential);

        ClientRegistrationFingerprint.Compute(snapshot).Value.Should().Be(
            before, $"a store that {edit} must not change the credential validation approved");
    }

    [Fact]
    public void Writing_into_a_served_credential_leaves_the_store_s_credential_alone()
    {
        // The registration reaches host code through TokenIssuanceContext.Client, and a downcast
        // reaches its credentials. The in-memory repository keeps one credential instance for the
        // host's lifetime, so a write reaching it would change the secret for every later request.
        var credential = new MutablePbkdf2Secret();
        var snapshot = ClientRegistrationSnapshot.Of(new MutableRegistration { Credentials = [credential] });
        var served = (IPbkdf2ClientSecret)snapshot.Credentials.Single();

        served.Hash[0] ^= 0xFF;

        credential.Hash.Should().Equal(MutablePbkdf2Secret.OriginalHash);
    }

    [Fact]
    public void No_copied_collection_can_be_mutated_through_its_writable_interface()
    {
        // The registration reaches host code: TokenIssuanceContext.Client hands it to the host's
        // own ITokenIssuer. A HashSet behind an IReadOnlySet is read-only by convention only, and a
        // host that reached one and added a redirect URI would reopen this type's whole reason for
        // existing one layer further down.
        //
        // Every collection is exercised through ICollection<T> rather than checked against a list
        // of known-mutable types: a future edit could reach for a mutable collection no such list
        // happens to name, and the invariant is that mutation is refused, not that one spelling of
        // it is avoided.
        var snapshot = ClientRegistrationSnapshot.Of(FullyPopulated());

        // A string is IEnumerable and has nothing to mutate, so ClientId and DisplayName are not
        // members this test has anything to say about.
        var members = DeclaredProperties()
            .Select(p => (p.Name, Value: p.GetValue(snapshot)))
            .Where(member => member.Value is IEnumerable and not string)
            .Select(member => (member.Name, Collection: (IEnumerable)member.Value!));

        foreach (var (name, collection) in members)
        {
            var because = $"{name} must refuse mutation through every ICollection<T> it exposes";
            var before = collection.Cast<object>().ToList();

            var writable = collection.GetType().GetInterfaces()
                .Where(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(ICollection<>))
                .ToList();

            writable.Should().NotBeEmpty(
                $"{name} exposes no ICollection<T>, so this test cannot prove it refuses mutation");

            foreach (var clear in writable.Select(i => i.GetMethod(nameof(ICollection<object>.Clear))!))
            {
                var mutate = () => clear.Invoke(collection, null);

                mutate.Should().Throw<TargetInvocationException>()
                    .WithInnerException<NotSupportedException>(because);
            }

            collection.Cast<object>().Should().BeEquivalentTo(before, because);
        }
    }

    [Fact]
    public void Adding_to_a_copied_set_through_its_mutable_interface_is_refused()
    {
        // The other half of the guard above: even reached as ICollection<string> — which every set
        // implements — the wrapper has no working Add.
        var snapshot = ClientRegistrationSnapshot.Of(FullyPopulated());

        var add = () => ((ICollection<string>)snapshot.RedirectUris).Add("https://attacker.example.com/callback");

        add.Should().Throw<NotSupportedException>();
        snapshot.RedirectUris.Should().NotContain("https://attacker.example.com/callback");
    }

    [Fact]
    public void String_sets_are_rebuilt_with_ordinal_comparison()
    {
        // The IClientMetadata string-set invariant says a set's own comparer is not trusted. Past
        // the snapshot it cannot be the wrong one, because the framework chose it — so a
        // case-insensitive registration can no longer make a consumer match a URI it did not register.
        var snapshot = ClientRegistrationSnapshot.Of(new MutableRegistration
        {
            RedirectUris = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "https://app.example.com/Callback" },
        });

        snapshot.RedirectUris.Contains("https://app.example.com/callback").Should().BeFalse();
    }

    [Fact]
    public void A_null_AllowedSigningAlgorithms_stays_null()
    {
        // Null means "inherit the server's advertised set" and empty means "none permitted"; a
        // copy that flattened one into the other would change what the client may be issued.
        ClientRegistrationSnapshot.Of(new MutableRegistration { AllowedSigningAlgorithms = null })
            .AllowedSigningAlgorithms.Should().BeNull();
    }

    [Fact]
    public void A_throwing_member_propagates_to_the_caller()
    {
        // ValidatedClientResolver turns this into an unknown client. The snapshot's job is to let
        // it through, not to invent a value for a registration that cannot be read.
        var act = () => ClientRegistrationSnapshot.Of(new ThrowingRegistration());

        act.Should().Throw<InvalidOperationException>();
    }

    public static TheoryData<string, Action<MutableRegistration>> MutatedMembers()
    {
        var data = new TheoryData<string, Action<MutableRegistration>>();
        foreach (var (member, mutate) in MemberMutations())
            data.Add(member, mutate);

        return data;
    }

    // ── Fixture ───────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Every property of the interface. <c>Type.GetProperties()</c> on an interface does not return
    /// inherited members, so the whole implemented-interface set is walked — naming the interfaces
    /// by hand would let a member on a newly inserted base interface escape both guards.
    /// </summary>
    private static IEnumerable<PropertyInfo> DeclaredProperties() =>
        typeof(IClientRegistration).GetInterfaces()
            .Append(typeof(IClientRegistration))
            .SelectMany(t => t.GetProperties())
            .DistinctBy(p => p.Name, StringComparer.Ordinal);

    /// <summary>
    /// A registration with every member set away from the value an uncopied one would hold. It is
    /// not a valid registration — a public client with a credential, for one — which neither the
    /// snapshot nor the fingerprint cares about; only the validator does.
    /// </summary>
    private static MutableRegistration FullyPopulated() => new()
    {
        ClientId = "fully-populated",
        IsPublic = true,
        EnableZkdErrorCodes = true,
        DisplayName = "Fully Populated",
        InitiateLoginUri = "https://app.example.com/login",
        RequireConsent = true,
        SkipLogoutConfirmation = true,
        AllowNonceInsteadOfPkce = true,
        RedirectUris = Ordinal("https://app.example.com/callback"),
        PostLogoutRedirectUris = Ordinal("https://app.example.com/bye"),
        AllowedScopes = Ordinal("openid", "profile"),
        AllowedTokenEndpointAuthMethods = Ordinal(TokenEndpointAuthMethods.None),
        AllowedGrantTypes = new HashSet<GrantType> { GrantType.AuthorizationCode },
        AllowedResponseTypes = new HashSet<ResponseType> { ResponseType.Code },
        AllowedResponseModes = new HashSet<ResponseMode> { ResponseMode.Query },
        AllowedPromptValues = new HashSet<PromptValue> { PromptValue.Login },
        AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.RS256 },
        AccessTokenLifetime = TimeSpan.FromMinutes(10),
        IdTokenLifetime = TimeSpan.FromMinutes(5),
        AdditionalIdTokenClaims = ["tenant"],
        AdditionalUserInfoClaims = ["department"],
        AdditionalAccessTokenClaims = ["region"],
        // The framework's own type, because the snapshot serves every IPbkdf2ClientSecret as one and
        // the fingerprint includes the credential's type.
        Credentials = [new Pbkdf2ClientSecret(600_000, [9, 9, 9], [1, 2, 3])],
    };

    public static TheoryData<string, Action<MutablePbkdf2Secret>> CredentialEdits() => new()
    {
        { "writes into the salt", c => c.Salt[0] ^= 0xFF },
        { "writes into the hash", c => c.Hash[0] ^= 0xFF },
        { "changes the iteration count", c => c.Iterations++ },
    };

    private static Dictionary<string, Action<MutableRegistration>> MemberMutations() =>
        new(StringComparer.Ordinal)
        {
            ["ClientId"] = r => r.ClientId = "other-client",
            ["IsPublic"] = r => r.IsPublic = false,
            ["EnableZkdErrorCodes"] = r => r.EnableZkdErrorCodes = true,
            ["DisplayName"] = r => r.DisplayName = "Other App",
            ["InitiateLoginUri"] = r => r.InitiateLoginUri = "https://app.example.com/start",
            ["RequireConsent"] = r => r.RequireConsent = false,
            ["SkipLogoutConfirmation"] = r => r.SkipLogoutConfirmation = true,
            ["AllowNonceInsteadOfPkce"] = r => r.AllowNonceInsteadOfPkce = true,
            ["RedirectUris"] = r => r.RedirectUris = Ordinal("https://app.example.com/other"),
            ["PostLogoutRedirectUris"] = r => r.PostLogoutRedirectUris = Ordinal("https://app.example.com/bye"),
            ["AllowedScopes"] = r => r.AllowedScopes = Ordinal("openid", "admin"),
            ["AllowedTokenEndpointAuthMethods"] = r =>
                r.AllowedTokenEndpointAuthMethods = Ordinal(TokenEndpointAuthMethods.ClientSecretBasic),
            ["AllowedGrantTypes"] = r => r.AllowedGrantTypes = new HashSet<GrantType> { GrantType.RefreshToken },
            ["AllowedResponseTypes"] = r => r.AllowedResponseTypes = new HashSet<ResponseType>(),
            ["AllowedResponseModes"] = r => r.AllowedResponseModes = new HashSet<ResponseMode> { ResponseMode.FormPost },
            ["AllowedPromptValues"] = r => r.AllowedPromptValues = new HashSet<PromptValue> { PromptValue.Login },
            ["AllowedSigningAlgorithms"] = r =>
                r.AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.RS256 },
            ["AccessTokenLifetime"] = r => r.AccessTokenLifetime = TimeSpan.FromMinutes(10),
            ["IdTokenLifetime"] = r => r.IdTokenLifetime = TimeSpan.FromMinutes(1),
            ["AdditionalIdTokenClaims"] = r => r.AdditionalIdTokenClaims = ["tenant"],
            ["AdditionalUserInfoClaims"] = r => r.AdditionalUserInfoClaims = ["tenant"],
            ["AdditionalAccessTokenClaims"] = r => r.AdditionalAccessTokenClaims = ["tenant"],
            ["Credentials"] = r => r.Credentials = [new StubPbkdf2Secret()],
        };

    private static IReadOnlySet<string> Ordinal(params string[] values) =>
        new HashSet<string>(values, StringComparer.Ordinal);

    /// <summary>
    /// What a custom store is free to hand back: every member settable, so the test can change one
    /// after the snapshot has been taken.
    /// </summary>
    public sealed class MutableRegistration : IClientRegistration
    {
        public string ClientId { get; set; } = "client-1";

        public bool IsPublic { get; set; } = true;

        public bool EnableZkdErrorCodes { get; set; }

        public string? DisplayName { get; set; }

        public string? InitiateLoginUri { get; set; }

        public bool RequireConsent { get; set; } = true;

        public bool SkipLogoutConfirmation { get; set; }

        public bool AllowNonceInsteadOfPkce { get; set; }

        public IReadOnlySet<string> RedirectUris { get; set; } = Ordinal("https://app.example.com/callback");

        public IReadOnlySet<string> PostLogoutRedirectUris { get; set; } = Ordinal();

        public IReadOnlySet<string> AllowedScopes { get; set; } = Ordinal("openid", "profile");

        public IReadOnlySet<string> AllowedTokenEndpointAuthMethods { get; set; } = Ordinal(TokenEndpointAuthMethods.None);

        public IReadOnlySet<GrantType> AllowedGrantTypes { get; set; } = new HashSet<GrantType> { GrantType.AuthorizationCode };

        public IReadOnlySet<ResponseType> AllowedResponseTypes { get; set; } = new HashSet<ResponseType> { ResponseType.Code };

        public IReadOnlySet<ResponseMode> AllowedResponseModes { get; set; } = new HashSet<ResponseMode> { ResponseMode.Query };

        public IReadOnlySet<PromptValue> AllowedPromptValues { get; set; } = new HashSet<PromptValue>();

        public IReadOnlySet<SigningAlgorithm>? AllowedSigningAlgorithms { get; set; }

        public TimeSpan? AccessTokenLifetime { get; set; }

        public TimeSpan? IdTokenLifetime { get; set; }

        public IReadOnlyCollection<string> AdditionalIdTokenClaims { get; set; } = [];

        public IReadOnlyCollection<string> AdditionalUserInfoClaims { get; set; } = [];

        public IReadOnlyCollection<string> AdditionalAccessTokenClaims { get; set; } = [];

        public IReadOnlyList<IClientCredential> Credentials { get; set; } = [];
    }

    private sealed class ThrowingRegistration : IClientRegistration
    {
        public string ClientId => throw new InvalidOperationException("The store could not read this registration.");

        public bool IsPublic => true;

        public bool EnableZkdErrorCodes => false;

        public IReadOnlySet<string> RedirectUris => Ordinal();

        public IReadOnlySet<string> PostLogoutRedirectUris => Ordinal();

        public IReadOnlySet<string> AllowedScopes => Ordinal();

        public IReadOnlySet<string> AllowedTokenEndpointAuthMethods => Ordinal();

        public IReadOnlySet<GrantType> AllowedGrantTypes => new HashSet<GrantType>();

        public IReadOnlySet<ResponseType> AllowedResponseTypes => new HashSet<ResponseType>();

        public IReadOnlySet<ResponseMode> AllowedResponseModes => new HashSet<ResponseMode>();

        public IReadOnlyList<IClientCredential> Credentials => [];
    }

    private sealed class StubPbkdf2Secret : IPbkdf2ClientSecret
    {
        public int Iterations => 600_000;

        public byte[] Salt => [9, 9, 9];

        public byte[] Hash => [1, 2, 3];
    }

    /// <summary>
    /// A store entity implementing <see cref="IPbkdf2ClientSecret"/> directly, as an ORM entity
    /// would: its arrays are its own, and it hands them out rather than copies.
    /// </summary>
    public sealed class MutablePbkdf2Secret : IPbkdf2ClientSecret
    {
        public static IReadOnlyList<byte> OriginalHash { get; } = [1, 2, 3];

        public int Iterations { get; set; } = 600_000;

        public byte[] Salt { get; } = [9, 9, 9];

        public byte[] Hash { get; } = [.. OriginalHash];
    }
}
