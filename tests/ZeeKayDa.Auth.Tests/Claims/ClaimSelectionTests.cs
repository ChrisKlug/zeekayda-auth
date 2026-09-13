using System.Text.Json;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Tests.Claims;

/// <summary>
/// Which of a provider's claims land in which destination: per-scope lists unioned per
/// destination, client additions on top, reserved names stripped, repeats merged by the rules
/// that keep a consumer's <c>HasClaim</c> honest.
/// </summary>
public sealed class ClaimSelectionTests
{
    private static readonly ScopeDefinition OrdersRead = new()
    {
        Name = "orders.read",
        Audience = "https://orders.example.com/",
        AccessTokenClaims = ["role"],
        UserInfoClaims = ["customer_number"],
    };

    private static ClientRegistration Client(
        IReadOnlyCollection<string>? idToken = null,
        IReadOnlyCollection<string>? userInfo = null,
        IReadOnlyCollection<string>? accessToken = null) =>
        ClientRegistration.CreatePublic("app", ["https://app.example.com/cb"], [], ["openid"]) with
        {
            AdditionalIdTokenClaims = idToken ?? [],
            AdditionalUserInfoClaims = userInfo ?? [],
            AdditionalAccessTokenClaims = accessToken ?? [],
        };

    private static SelectedClaims Select(IReadOnlyList<ClaimRecord> pool, IReadOnlyList<ScopeDefinition> granted, IClientMetadata? client = null) =>
        ClaimSelection.Select(pool, ClaimSelectionPlan.For(granted, client ?? Client()));

    private static string Json(ClaimValue value) => JsonSerializer.Serialize(value);

    // ── The plan: what each destination wants ─────────────────────────────────────────────────

    [Fact]
    public void The_plan_unions_each_destination_over_the_granted_scopes_and_adds_the_client_additions()
    {
        var plan = ClaimSelectionPlan.For(
            [StandardScopes.OpenId, StandardScopes.Profile, OrdersRead],
            Client(idToken: ["tenant"], accessToken: ["tenant"]));

        plan.IdToken.Should().Contain(["name", "given_name", "tenant"]).And.NotContain("role");
        plan.AccessToken.Should().BeEquivalentTo(["role", "tenant"]);
        plan.UserInfo.Should().Contain(["name", "customer_number"]).And.NotContain("tenant");
        plan.All.Should().Contain(["name", "role", "tenant", "customer_number"]);
    }

    [Fact]
    public void The_plan_is_empty_for_a_scope_that_unlocks_nothing_and_a_client_that_adds_nothing()
    {
        var plan = ClaimSelectionPlan.For([new ScopeDefinition { Name = "api" }], Client());

        plan.All.Should().BeEmpty();
    }

    // ── Routing ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void A_claim_lands_only_in_the_destinations_that_want_it()
    {
        var selected = Select(
            [new("name", "Chris"), new("email", "chris@example.com"), new("role", "admin")],
            [StandardScopes.OpenId, StandardScopes.Profile, OrdersRead]);

        selected.IdToken.Keys.Should().BeEquivalentTo(["name"]);
        selected.AccessToken.Keys.Should().BeEquivalentTo(["role"]);
        selected.UserInfo.Keys.Should().BeEquivalentTo(["name"]);
    }

    [Fact]
    public void Adding_the_email_scope_unlocks_email_and_email_verified_in_the_ID_token()
    {
        var selected = Select(
            [new("name", "Chris"), new("email", "chris@example.com"), new("email_verified", true)],
            [StandardScopes.OpenId, StandardScopes.Profile, StandardScopes.Email]);

        selected.IdToken.Keys.Should().BeEquivalentTo(["name", "email", "email_verified"]);
        Json(selected.IdToken["email_verified"]).Should().Be("true");
    }

    [Fact]
    public void A_wanted_claim_the_provider_did_not_return_is_absent_not_null()
    {
        var selected = Select([new("name", "Chris")], [StandardScopes.Profile]);

        selected.IdToken.Should().NotContainKey("given_name");
    }

    [Fact]
    public void A_claim_no_destination_wants_is_dropped()
    {
        var selected = Select([new("shoe_size", 43)], [StandardScopes.Profile]);

        selected.IdToken.Should().BeEmpty();
        selected.AccessToken.Should().BeEmpty();
        selected.UserInfo.Should().BeEmpty();
    }

    [Fact]
    public void A_client_addition_selects_a_claim_no_scope_unlocks()
    {
        var selected = Select(
            [new("tenant", "acme")],
            [StandardScopes.OpenId],
            Client(idToken: ["tenant"], accessToken: ["tenant"]));

        selected.IdToken.Keys.Should().BeEquivalentTo(["tenant"]);
        selected.AccessToken.Keys.Should().BeEquivalentTo(["tenant"]);
        selected.UserInfo.Should().BeEmpty();
    }

    [Fact]
    public void Claim_names_are_matched_ordinally()
    {
        var selected = Select([new("Name", "Chris")], [StandardScopes.Profile]);

        selected.IdToken.Should().BeEmpty("a scope unlocking 'name' does not unlock 'Name'");
    }

    [Fact]
    public void Both_destinations_see_the_same_value_for_a_claim_they_both_want()
    {
        var scope = new ScopeDefinition { Name = "s", IdTokenClaims = ["role"], AccessTokenClaims = ["role"] };

        var selected = Select([new("role", "admin"), new("role", "editor")], [scope]);

        selected.IdToken["role"].Should().Be(selected.AccessToken["role"]);
    }

    // ── Reserved names: a provider cannot re-assert the grant ─────────────────────────────────

    [Theory]
    [InlineData("sub")]
    [InlineData("iss")]
    [InlineData("aud")]
    [InlineData("exp")]
    [InlineData("iat")]
    [InlineData("auth_time")]
    [InlineData("nonce")]
    [InlineData("amr")]
    [InlineData("scope")]
    [InlineData("client_id")]
    [InlineData("at_hash")]
    public void A_reserved_protocol_name_is_stripped_even_when_a_scope_lists_it(string name)
    {
        var scope = new ScopeDefinition { Name = "s", IdTokenClaims = [name], AccessTokenClaims = [name] };

        var selected = Select([new(name, "attacker")], [scope]);

        selected.IdToken.Should().BeEmpty();
        selected.AccessToken.Should().BeEmpty();
    }

    [Theory]
    [InlineData("Sub")]
    [InlineData("AUD")]
    [InlineData("ZKD:sid")]
    public void Reserved_names_are_stripped_ignoring_case(string name)
    {
        var scope = new ScopeDefinition { Name = "s", IdTokenClaims = [name] };

        var selected = Select([new(name, "attacker")], [scope]);

        selected.IdToken.Should().BeEmpty("a resource server's FindFirst is case-insensitive, so 'Sub' would win the lookup");
    }

    [Fact]
    public void A_name_in_the_framework_namespace_is_stripped()
    {
        var scope = new ScopeDefinition { Name = "s", IdTokenClaims = ["zkd:anything"] };

        var selected = Select([new("zkd:anything", "x")], [scope]);

        selected.IdToken.Should().BeEmpty();
    }

    // ── Merging repeats ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void Repeated_string_records_merge_into_one_array_in_the_order_returned()
    {
        var selected = Select(
            [new("role", "viewer"), new("role", "admin"), new("role", "editor")],
            [OrdersRead]);

        Json(selected.AccessToken["role"]).Should().Be("[\"viewer\",\"admin\",\"editor\"]");
    }

    [Fact]
    public void Repeated_number_records_merge_into_one_array()
    {
        var scope = new ScopeDefinition { Name = "s", AccessTokenClaims = ["group_id"] };

        var selected = Select([new("group_id", 7), new("group_id", 9L)], [scope]);

        Json(selected.AccessToken["group_id"]).Should().Be("[7,9]");
    }

    [Fact]
    public void Repeated_records_are_not_deduplicated()
    {
        var selected = Select([new("role", "admin"), new("role", "admin")], [OrdersRead]);

        Json(selected.AccessToken["role"]).Should().Be("[\"admin\",\"admin\"]");
    }

    [Fact]
    public void A_single_record_is_written_as_a_scalar()
    {
        var selected = Select([new("role", "admin")], [OrdersRead]);

        Json(selected.AccessToken["role"]).Should().Be("\"admin\"");
    }

    [Fact]
    public void A_repeated_boolean_aborts_issuance()
    {
        var scope = new ScopeDefinition { Name = "s", AccessTokenClaims = ["is_admin"] };

        var act = () => Select([new("is_admin", true), new("is_admin", false)], [scope]);

        act.Should().Throw<InvalidOperationException>().WithMessage("*'is_admin'*")
            .And.Message.Should().NotContain("true", "the message names the claim, not its values");
    }

    [Fact]
    public void A_repeat_mixing_strings_and_numbers_aborts_issuance()
    {
        var scope = new ScopeDefinition { Name = "s", AccessTokenClaims = ["x"] };

        var act = () => Select([new("x", "a"), new("x", 1)], [scope]);

        act.Should().Throw<InvalidOperationException>().WithMessage("*'x'*");
    }

    [Fact]
    public void A_repeated_object_aborts_issuance()
    {
        var scope = new ScopeDefinition { Name = "s", IdTokenClaims = ["home"] };

        var act = () => Select([new("home", new AddressClaim { Country = "SE" }), new("home", new AddressClaim { Country = "NO" })], [scope]);

        act.Should().Throw<InvalidOperationException>();
    }

    [Theory]
    [InlineData("email")]
    [InlineData("name")]
    [InlineData("updated_at")]
    public void A_repeat_of_a_single_valued_standard_claim_aborts_issuance(string claim)
    {
        var act = () => Select([new(claim, "a"), new(claim, "b")], [StandardScopes.Profile, StandardScopes.Email]);

        act.Should().Throw<InvalidOperationException>().WithMessage($"*'{claim}'*");
    }

    [Fact]
    public void An_illegal_repeat_aborts_even_when_no_destination_wants_the_claim()
    {
        var act = () => Select([new("flag", true), new("flag", false)], [StandardScopes.OpenId]);

        act.Should().Throw<InvalidOperationException>("a provider bug is a bug wherever it sits in the pool");
    }

    [Fact]
    public void A_provider_wanting_an_array_of_anything_else_returns_From_once()
    {
        var scope = new ScopeDefinition { Name = "s", AccessTokenClaims = ["flags"] };

        var selected = Select([new("flags", ClaimValue.From(new[] { true, false }))], [scope]);

        Json(selected.AccessToken["flags"]).Should().Be("[true,false]");
    }

    // ── Provider bugs ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void A_default_record_in_the_pool_aborts_issuance()
    {
        var act = () => Select([new("name", "Chris"), default], [StandardScopes.Profile]);

        act.Should().Throw<InvalidOperationException>().WithMessage("*default ClaimRecord*");
    }

    [Fact]
    public void A_null_addition_collection_on_a_custom_registration_is_treated_as_empty()
    {
        var plan = ClaimSelectionPlan.For([StandardScopes.OpenId], new NullAdditionsClient());

        plan.All.Should().BeEquivalentTo(["sub"]);
    }

    private sealed class NullAdditionsClient : IClientMetadata
    {
        public string ClientId => "custom";
        public bool IsPublic => true;
        public IReadOnlySet<string> RedirectUris => new HashSet<string>();
        public IReadOnlySet<string> PostLogoutRedirectUris => new HashSet<string>();
        public IReadOnlySet<string> AllowedScopes => new HashSet<string> { "openid" };
        public IReadOnlySet<GrantType> AllowedGrantTypes => new HashSet<GrantType>();
        public IReadOnlySet<ResponseType> AllowedResponseTypes => new HashSet<ResponseType>();
        public IReadOnlySet<ResponseMode> AllowedResponseModes => new HashSet<ResponseMode>();
        public IReadOnlySet<string> AllowedTokenEndpointAuthMethods => new HashSet<string>();
        public bool EnableZkdErrorCodes => false;
        public IReadOnlyCollection<string> AdditionalIdTokenClaims => null!;
        public IReadOnlyCollection<string> AdditionalUserInfoClaims => null!;
        public IReadOnlyCollection<string> AdditionalAccessTokenClaims => null!;
    }
}
