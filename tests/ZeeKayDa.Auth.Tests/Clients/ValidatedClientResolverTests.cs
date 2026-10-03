using FluentAssertions;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Tests.Clients;

public class ValidatedClientResolverTests
{
    [Fact]
    public async Task Valid_registration_is_served()
    {
        var client = NewClient();
        var resolver = Resolver(client, new PassingValidator());

        var result = await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);

        // A copy, never the store's own instance — see ClientRegistrationSnapshot.
        result.Should().NotBeNull().And.NotBeSameAs(client);
        result!.ClientId.Should().Be(client.ClientId);
        result.RedirectUris.Should().BeEquivalentTo(client.RedirectUris);
        result.AllowedScopes.Should().BeEquivalentTo(client.AllowedScopes);
    }

    [Fact]
    public async Task A_registration_edited_after_it_was_validated_does_not_change_what_was_served()
    {
        var redirectUris = new HashSet<string>(StringComparer.Ordinal) { "https://app.example.com/callback" };
        var resolver = Resolver(NewClient() with { RedirectUris = redirectUris }, new PassingValidator());

        var result = await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);
        redirectUris.Add("https://attacker.example.com/callback");

        // Exact-match redirect validation is only as trustworthy as the set it matches against. A
        // store free to edit that set after the verdict would have the authorize endpoint accept a
        // URI validation never saw.
        result!.RedirectUris.Should().NotContain("https://attacker.example.com/callback");
    }

    [Fact]
    public async Task A_registration_that_cannot_be_read_is_served_as_unknown_client()
    {
        var resolver = new ValidatedClientResolver(
            new ThrowingRepository(), new PassingValidator(), NullLogger());

        var result = await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);

        // A registration is an extension point, so a getter may throw. Fail closed: unknown
        // client, not a 500 out of every protocol endpoint.
        result.Should().BeNull();
    }

    [Fact]
    public async Task A_registration_that_cannot_be_read_logs_critical_naming_the_client_id()
    {
        var logger = new CapturingSanitizingLogger<ValidatedClientResolver>();
        var resolver = new ValidatedClientResolver(new ThrowingRepository(), new PassingValidator(), logger);

        await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);

        // The registration's own ClientId is unreadable, so the looked-up one is what names it —
        // an operator with neither would have nothing to go on.
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical && e.Message.Contains("client-1"));
    }

    [Fact]
    public async Task A_registration_that_cannot_be_read_logs_critical_once_however_many_lookups()
    {
        var logger = new CapturingSanitizingLogger<ValidatedClientResolver>();
        var resolver = new ValidatedClientResolver(new ThrowingRepository(), new PassingValidator(), logger);

        await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);
        await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);

        // An unauthenticated caller naming this client_id must not be able to drive the log level
        // that pages on-call as fast as it can send.
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task An_unreadable_registration_reached_under_many_client_ids_logs_critical_once()
    {
        var logger = new CapturingSanitizingLogger<ValidatedClientResolver>();
        var resolver = new ValidatedClientResolver(new ThrowingRepository(), new PassingValidator(), logger);

        await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);
        await resolver.FindClientWithCredentialsAsync("CLIENT-1", TestContext.Current.CancellationToken);
        await resolver.FindClientWithCredentialsAsync("Client-1", TestContext.Current.CancellationToken);

        // A store resolving several spellings of one id to one registration is the ordinary case —
        // a case-insensitive database column. Keying suppression by the requested id would let an
        // unauthenticated caller spend a key per spelling and buy the critical log back.
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task A_registration_revalidated_on_every_lookup_logs_critical_once()
    {
        var logger = new CapturingSanitizingLogger<ValidatedClientResolver>();
        var resolver = new ValidatedClientResolver(
            new RevisingRepository(),
            new RejectingValidator(),
            logger);

        await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);
        await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);

        // A registration whose content changes on every lookup is still the same failure.
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task A_registration_that_fails_a_second_different_way_is_logged_again()
    {
        var logger = new CapturingSanitizingLogger<ValidatedClientResolver>();
        var resolver = new ValidatedClientResolver(
            new RevisingRepository(),
            new DifferentRuleEachTimeValidator(),
            logger);

        await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);
        await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);

        // Suppression is keyed by the failure as well as the client_id. A registration breaking a
        // second, different way is a fact the operator has not been told yet.
        logger.Entries.Should().HaveCount(2).And.OnlyContain(e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task A_failure_reworded_on_every_validation_logs_critical_once()
    {
        var logger = new CapturingSanitizingLogger<ValidatedClientResolver>();
        var resolver = new ValidatedClientResolver(
            new RevisingRepository(),
            new RewordingValidator(),
            logger);

        await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);
        await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);
        await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);

        // Suppression keys on the rule code, never the message. A host validator free to put a
        // timestamp or an attempt counter in its message would otherwise mint a key and a Critical
        // entry per revalidation, and eventually clear the whole suppression set.
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task The_same_rules_reported_in_a_different_order_log_critical_once()
    {
        var logger = new CapturingSanitizingLogger<ValidatedClientResolver>();
        var resolver = new ValidatedClientResolver(
            new RevisingRepository(),
            new ReorderingValidator(),
            logger);

        await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);
        await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);

        // Aggregated failures arrive in whatever order the validator reports them; the same set of
        // broken rules is the same failure however it is ordered.
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task Two_clients_whose_ids_and_rule_codes_run_together_are_both_logged()
    {
        var logger = new CapturingSanitizingLogger<ValidatedClientResolver>();

        // "ab" + "c_rule" and "a" + "bc_rule" concatenate to the same string, so a key built by
        // joining the two parts would collide and silence the second client's Critical entry.
        var resolver = new ValidatedClientResolver(
            new MultiClientRepository(
                ConfidentialClient("ab"),
                ConfidentialClient("a")),
            new CodePerClientValidator(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ab"] = "c_rule",
                ["a"] = "bc_rule",
            }),
            logger);

        await resolver.FindClientWithCredentialsAsync("ab", TestContext.Current.CancellationToken);
        await resolver.FindClientWithCredentialsAsync("a", TestContext.Current.CancellationToken);

        logger.Entries.Should().HaveCount(2).And.OnlyContain(e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task Two_rule_code_sets_that_join_identically_are_both_logged()
    {
        var logger = new CapturingSanitizingLogger<ValidatedClientResolver>();
        var resolver = new ValidatedClientResolver(
            new RevisingRepository(),
            new JoiningCodeSetsValidator(),
            logger);

        await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);
        await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);

        // A rule code is a host-supplied string with no syntax restriction, so the set of codes
        // cannot be identified by joining them: ["a; b", "c"] and ["a", "b; c"] join to the same
        // text. The second registration is broken a different way and the operator must hear so.
        logger.Entries.Should().HaveCount(2).And.OnlyContain(e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task Unknown_client_returns_null()
    {
        var resolver = Resolver(NewClient(), new PassingValidator());

        var result = await resolver.FindClientWithCredentialsAsync("no-such-client", TestContext.Current.CancellationToken);

        result.Should().BeNull();
    }

    [Fact]
    public async Task FindClientAsync_returns_the_validated_client()
    {
        var resolver = Resolver(NewClient(), new PassingValidator());

        var result = await resolver.FindClientAsync("client-1", TestContext.Current.CancellationToken);

        result.Should().NotBeNull().And.Subject.As<IClient>().ClientId.Should().Be("client-1");
    }

    [Fact]
    public async Task FindClientAsync_serves_an_invalid_registration_as_unknown()
    {
        var resolver = Resolver(NewClient(), new RejectingValidator());

        var result = await resolver.FindClientAsync("client-1", TestContext.Current.CancellationToken);

        result.Should().BeNull();
    }

    [Fact]
    public async Task Invalid_registration_is_served_as_unknown_client()
    {
        var resolver = Resolver(NewClient(), new RejectingValidator());

        var result = await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);

        result.Should().BeNull(
            "a registration failing validation must fail closed as unknown, never reach the protocol");
    }

    [Fact]
    public async Task Invalid_registration_logs_critical_for_the_operator()
    {
        var logger = new CapturingSanitizingLogger<ValidatedClientResolver>();
        var resolver = new ValidatedClientResolver(
            new SingleClientRepository(NewClient()), new RejectingValidator(), logger);

        await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);

        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task A_registration_mutated_in_place_is_revalidated()
    {
        var validator = new CountingValidator();
        var mutable = new MutableRepository(NewClient());
        var resolver = new ValidatedClientResolver(mutable, validator, NullLogger());

        await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);
        mutable.Current = NewClient() with
        {
            RedirectUris = new HashSet<string>(StringComparer.Ordinal) { "https://app.example.com/added" },
        };
        await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);

        // A store that edits a cached registration must not keep the old verdict: a stale "valid"
        // would bless a URI validation rejects.
        validator.Calls.Should().Be(2);
    }

    [Theory]
    [InlineData("")]
    [InlineData("client 1")]
    [InlineData("client/1")]
    public async Task A_malformed_client_id_never_reaches_the_repository(string clientId)
    {
        var repository = new CountingRepository();
        var resolver = new ValidatedClientResolver(repository, new PassingValidator(), NullLogger());

        var result = await resolver.FindClientWithCredentialsAsync(clientId, TestContext.Current.CancellationToken);

        result.Should().BeNull();
        repository.Calls.Should().Be(0, "a repository only ever sees a well-formed client_id");
    }

    [Fact]
    public async Task A_client_id_over_the_length_limit_never_reaches_the_repository()
    {
        var repository = new CountingRepository();
        var resolver = new ValidatedClientResolver(repository, new PassingValidator(), NullLogger());

        await resolver.FindClientWithCredentialsAsync(new string('a', 201), TestContext.Current.CancellationToken);

        repository.Calls.Should().Be(0);
    }

    [Fact]
    public async Task A_repository_that_throws_propagates_rather_than_answering_unknown()
    {
        var resolver = new ValidatedClientResolver(new FailingRepository(), new PassingValidator(), NullLogger());

        var act = async () => await resolver.FindClientWithCredentialsAsync("client-1", TestContext.Current.CancellationToken);

        // An outage is the server's failure, not the client's: answering unknown would turn it
        // into invalid_client for every caller.
        await act.Should().ThrowAsync<TimeoutException>();
    }

    // ── Fixture ───────────────────────────────────────────────────────────────────────────────

    private static Client NewClient() =>
        Client.CreatePublic(
            "client-1",
            redirectUris: ["https://app.example.com/callback"],
            postLogoutRedirectUris: [],
            allowedScopes: ["openid"]);

    private static Client ConfidentialClient(string clientId = "client-1") =>
        Client.CreateConfidential(
            clientId,
            new ClientSecret("$fake$x"),
            redirectUris: ["https://app.example.com/callback"],
            postLogoutRedirectUris: [],
            allowedScopes: ["openid"]);

    private static ValidatedClientResolver Resolver(
        IClientWithCredentials client, IClientRegistrationValidator validator) =>
        new(new SingleClientRepository(client), validator, NullLogger());

    private static SanitizingLogger<ValidatedClientResolver> NullLogger() => NullSanitizingLogger<ValidatedClientResolver>.Instance;

    private sealed class SingleClientRepository(IClientWithCredentials client) : IClientRepository
    {
        public Task<IClientWithCredentials?> FindByClientIdAsync(
            string clientId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IClientWithCredentials?>(
                string.Equals(clientId, client.ClientId, StringComparison.Ordinal) ? client : null);
    }

    private sealed class MultiClientRepository(params IClientWithCredentials[] clients) : IClientRepository
    {
        public Task<IClientWithCredentials?> FindByClientIdAsync(
            string clientId, CancellationToken cancellationToken = default) =>
            Task.FromResult(
                clients.FirstOrDefault(c => string.Equals(c.ClientId, clientId, StringComparison.Ordinal)));
    }

    private sealed class MutableRepository(IClientWithCredentials current) : IClientRepository
    {
        public IClientWithCredentials Current { get; set; } = current;

        public Task<IClientWithCredentials?> FindByClientIdAsync(
            string clientId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IClientWithCredentials?>(Current);
    }

    private sealed class ThrowingRepository : IClientRepository
    {
        public Task<IClientWithCredentials?> FindByClientIdAsync(
            string clientId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IClientWithCredentials?>(new ThrowingRegistration());
    }

    private sealed class ThrowingRegistration : IClientWithCredentials
    {
        public string ClientId => throw new InvalidOperationException("This registration cannot be read.");

        public bool IsPublic => true;

        public bool EnableZkdErrorCodes => false;

        public IReadOnlySet<string> RedirectUris => new HashSet<string>(StringComparer.Ordinal);

        public IReadOnlySet<string> PostLogoutRedirectUris => new HashSet<string>(StringComparer.Ordinal);

        public IReadOnlySet<string> AllowedScopes => new HashSet<string>(StringComparer.Ordinal);

        public IReadOnlySet<string> AllowedTokenEndpointAuthMethods => new HashSet<string>(StringComparer.Ordinal);

        public IReadOnlySet<GrantType> AllowedGrantTypes => new HashSet<GrantType>();

        public IReadOnlySet<ResponseType> AllowedResponseTypes => new HashSet<ResponseType>();

        public IReadOnlySet<ResponseMode> AllowedResponseModes => new HashSet<ResponseMode>();

        public IReadOnlyList<ClientSecret> Secrets => [];
    }

    private sealed class CountingRepository : IClientRepository
    {
        public int Calls { get; private set; }

        public Task<IClientWithCredentials?> FindByClientIdAsync(
            string clientId, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult<IClientWithCredentials?>(null);
        }
    }

    private sealed class FailingRepository : IClientRepository
    {
        public Task<IClientWithCredentials?> FindByClientIdAsync(
            string clientId, CancellationToken cancellationToken = default) =>
            throw new TimeoutException("The client store did not answer.");
    }

    /// <summary>
    /// Hands out a registration whose content differs on every lookup.
    /// </summary>
    private sealed class RevisingRepository : IClientRepository
    {
        private int _revision;

        public Task<IClientWithCredentials?> FindByClientIdAsync(
            string clientId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IClientWithCredentials?>(
                ConfidentialClient() with { DisplayName = $"revision {Interlocked.Increment(ref _revision)}" });
    }

    private sealed class PassingValidator : IClientRegistrationValidator
    {
        public void Validate(IClientWithCredentials client)
        {
        }
    }

    private sealed class RejectingValidator : IClientRegistrationValidator
    {
        public void Validate(IClientWithCredentials client) =>
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure("test_rule", "Deliberately rejected by the test."));
    }

    /// <summary>Rejects every registration, for the rule this test named for its <c>client_id</c>.</summary>
    private sealed class CodePerClientValidator(IReadOnlyDictionary<string, string> codesByClientId)
        : IClientRegistrationValidator
    {
        public void Validate(IClientWithCredentials client) =>
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    codesByClientId[client.ClientId], "Deliberately rejected by the test."));
    }

    /// <summary>Rejects every registration, breaking a different rule each time.</summary>
    private sealed class DifferentRuleEachTimeValidator : IClientRegistrationValidator
    {
        private int _calls;

        public void Validate(IClientWithCredentials client)
        {
            var call = ++_calls;
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure($"test_rule_{call}", $"Rejected by the test, rule {call}."));
        }
    }

    /// <summary>
    /// Rejects every registration for the same rule, worded differently each time — a host
    /// validator whose message carries a timestamp or an attempt counter.
    /// </summary>
    private sealed class RewordingValidator : IClientRegistrationValidator
    {
        private int _calls;

        public void Validate(IClientWithCredentials client) =>
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure("test_rule", $"Rejected by the test, attempt {++_calls}."));
    }

    /// <summary>
    /// Rejects every registration for two rules whose codes carry the delimiter a naive key would
    /// join on, reporting a different set of them each time.
    /// </summary>
    private sealed class JoiningCodeSetsValidator : IClientRegistrationValidator
    {
        private bool _second;

        public void Validate(IClientWithCredentials client)
        {
            _second = !_second;

            throw _second
                ? new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure("a; b", "Rules a and b were broken."),
                    new ZeeKayDaConfigurationFailure("c", "Rule c was broken."))
                : new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure("a", "Rule a was broken."),
                    new ZeeKayDaConfigurationFailure("b; c", "Rules b and c were broken."));
        }
    }

    /// <summary>Rejects every registration, reporting two rules in a different order each time.</summary>
    private sealed class ReorderingValidator : IClientRegistrationValidator
    {
        private bool _flipped;

        public void Validate(IClientWithCredentials client)
        {
            var first = new ZeeKayDaConfigurationFailure("test_rule_a", "Rule A was broken.");
            var second = new ZeeKayDaConfigurationFailure("test_rule_b", "Rule B was broken.");
            _flipped = !_flipped;

            throw _flipped
                ? new ZeeKayDaConfigurationException(first, second)
                : new ZeeKayDaConfigurationException(second, first);
        }
    }

    private sealed class CountingValidator : IClientRegistrationValidator
    {
        public int Calls { get; private set; }

        public void Validate(IClientWithCredentials client) => Calls++;
    }

}
