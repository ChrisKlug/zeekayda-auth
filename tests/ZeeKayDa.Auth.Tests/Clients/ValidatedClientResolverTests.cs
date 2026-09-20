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
        var client = Client();
        var resolver = Resolver(client, new PassingValidator());

        var result = await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

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
        var resolver = Resolver(Client() with { RedirectUris = redirectUris }, new PassingValidator());

        var result = await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);
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

        var result = await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

        // A registration is an extension point, so a getter may throw. Fail closed: unknown
        // client, not a 500 out of every protocol endpoint.
        result.Should().BeNull();
    }

    [Fact]
    public async Task A_registration_that_cannot_be_read_logs_critical_naming_the_client_id()
    {
        var logger = new CapturingLogger();
        var resolver = new ValidatedClientResolver(new ThrowingRepository(), new PassingValidator(), logger);

        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

        // The registration's own ClientId is unreadable, so the looked-up one is what names it —
        // an operator with neither would have nothing to go on.
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical && e.Message.Contains("client-1"));
    }

    [Fact]
    public async Task A_registration_that_cannot_be_read_logs_critical_once_however_many_lookups()
    {
        var logger = new CapturingLogger();
        var resolver = new ValidatedClientResolver(new ThrowingRepository(), new PassingValidator(), logger);

        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);
        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

        // An unreadable registration never reaches the verdict cache, so suppressing by verdict
        // instance wrote a Critical entry per request: an unauthenticated caller naming this
        // client_id could drive the log level that pages on-call as fast as it could send.
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task An_unreadable_registration_reached_under_many_client_ids_logs_critical_once()
    {
        var logger = new CapturingLogger();
        var resolver = new ValidatedClientResolver(new ThrowingRepository(), new PassingValidator(), logger);

        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);
        await resolver.FindByClientIdAsync("CLIENT-1", TestContext.Current.CancellationToken);
        await resolver.FindByClientIdAsync("Client-1", TestContext.Current.CancellationToken);

        // A store resolving several spellings of one id to one registration is the ordinary case —
        // a case-insensitive database column. Keying suppression by the requested id would let an
        // unauthenticated caller spend a key per spelling and buy the critical log back.
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task A_registration_validated_uncached_logs_critical_once_however_many_lookups()
    {
        var logger = new CapturingLogger();
        var resolver = new ValidatedClientResolver(
            new SingleClientRepository(ConfidentialClient(new CopyingCredential())),
            new RejectingValidator(),
            logger);

        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);
        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

        // A custom IClientCredential has no content to fingerprint, so this registration is
        // revalidated on every lookup by design — which also gave it a fresh verdict, and so a
        // fresh Critical entry, every time.
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task A_registration_that_fails_a_second_different_way_is_logged_again()
    {
        var logger = new CapturingLogger();
        var resolver = new ValidatedClientResolver(
            new SingleClientRepository(ConfidentialClient(new CopyingCredential())),
            new DifferentRuleEachTimeValidator(),
            logger);

        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);
        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

        // Suppression is keyed by the failure as well as the client_id. A registration breaking a
        // second, different way is a fact the operator has not been told yet.
        logger.Entries.Should().HaveCount(2).And.OnlyContain(e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task A_failure_reworded_on_every_validation_logs_critical_once()
    {
        var logger = new CapturingLogger();
        var resolver = new ValidatedClientResolver(
            new SingleClientRepository(ConfidentialClient(new CopyingCredential())),
            new RewordingValidator(),
            logger);

        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);
        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);
        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

        // Suppression keys on the rule code, never the message. A host validator free to put a
        // timestamp or an attempt counter in its message would otherwise mint a key and a Critical
        // entry per request on the uncached path, and eventually clear the whole suppression set.
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task The_same_rules_reported_in_a_different_order_log_critical_once()
    {
        var logger = new CapturingLogger();
        var resolver = new ValidatedClientResolver(
            new SingleClientRepository(ConfidentialClient(new CopyingCredential())),
            new ReorderingValidator(),
            logger);

        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);
        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

        // Aggregated failures arrive in whatever order the validator reports them; the same set of
        // broken rules is the same failure however it is ordered.
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task Two_clients_whose_ids_and_rule_codes_run_together_are_both_logged()
    {
        var logger = new CapturingLogger();

        // Length prefixes, not a separator: "ab" + "c_rule" and "a" + "bc_rule" concatenate to the
        // same string, so a key built by joining the two parts would collide and silence the
        // second client's Critical entry — the operator would never hear about that registration.
        var resolver = new ValidatedClientResolver(
            new MultiClientRepository(
                ConfidentialClient(new CopyingCredential(), "ab"),
                ConfidentialClient(new CopyingCredential(), "a")),
            new CodePerClientValidator(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ab"] = "c_rule",
                ["a"] = "bc_rule",
            }),
            logger);

        await resolver.FindByClientIdAsync("ab", TestContext.Current.CancellationToken);
        await resolver.FindByClientIdAsync("a", TestContext.Current.CancellationToken);

        logger.Entries.Should().HaveCount(2).And.OnlyContain(e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task Two_rule_code_sets_that_join_identically_are_both_logged()
    {
        var logger = new CapturingLogger();
        var resolver = new ValidatedClientResolver(
            new SingleClientRepository(ConfidentialClient(new CopyingCredential())),
            new JoiningCodeSetsValidator(),
            logger);

        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);
        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

        // A rule code is a host-supplied string with no syntax restriction, so the set of codes
        // cannot be identified by joining them: ["a; b", "c"] and ["a", "b; c"] join to the same
        // text. The second registration is broken a different way and the operator must hear so.
        logger.Entries.Should().HaveCount(2).And.OnlyContain(e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task Unknown_client_returns_null()
    {
        var resolver = Resolver(Client(), new PassingValidator());

        var result = await resolver.FindByClientIdAsync("no-such-client", TestContext.Current.CancellationToken);

        result.Should().BeNull();
    }

    [Fact]
    public async Task Invalid_registration_is_served_as_unknown_client()
    {
        var resolver = Resolver(Client(), new RejectingValidator());

        var result = await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

        result.Should().BeNull(
            "a registration failing validation must fail closed as unknown, never reach the protocol");
    }

    [Fact]
    public async Task Invalid_registration_logs_critical_for_the_operator()
    {
        var logger = new CapturingLogger();
        var resolver = new ValidatedClientResolver(
            new SingleClientRepository(Client()), new RejectingValidator(), logger);

        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task Verdict_is_memoized_for_a_cached_registration()
    {
        var validator = new CountingValidator();
        var resolver = Resolver(Client(), validator);

        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);
        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

        validator.Calls.Should().Be(1,
            "a repository serving a cached instance must not pay validation per lookup");
    }

    [Fact]
    public async Task Fresh_instances_with_equal_content_are_validated_once()
    {
        var validator = new CountingValidator();
        var resolver = new ValidatedClientResolver(
            new FreshInstanceRepository(), validator, NullLogger());

        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);
        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

        // Validation runs a 600,000-iteration PBKDF2 (the empty-secret probe). Instance-keyed
        // memoization made a store that hands out fresh instances per lookup — an EF Core
        // repository, say — pay that on every unauthenticated authorize request, which is a
        // CPU-exhaustion lever keyed on a public client_id. Content keying removes it.
        validator.Calls.Should().Be(1);
    }

    [Fact]
    public async Task A_registration_mutated_in_place_is_revalidated()
    {
        var validator = new CountingValidator();
        var mutable = new MutableRepository(Client());
        var resolver = new ValidatedClientResolver(mutable, validator, NullLogger());

        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);
        mutable.Current = Client() with
        {
            RedirectUris = new HashSet<string>(StringComparer.Ordinal) { "https://app.example.com/added" },
        };
        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

        // A store that edits a cached registration must not keep the old verdict: the matcher
        // reads the live redirect set, so a stale "valid" would bless a URI validation rejects.
        validator.Calls.Should().Be(2);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A_credential_whose_first_Snapshot_is_not_a_copy_is_served_as_unknown_whatever_it_answers_later(
        bool returnsNull)
    {
        // The snapshot asks each credential once and keeps that answer. A credential that hands back
        // itself (or null) the first time and a real copy afterwards must not pass because something
        // asked again — the validator here passes everything, so the snapshot's own check is all
        // that stands between the store's instance and the protocol.
        var resolver = Resolver(
            ConfidentialClient(new FirstCallUncopiedCredential(returnsNull)), new PassingValidator());

        var result = await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

        result.Should().BeNull();
    }

    [Theory]
    [InlineData(false, "returned the same instance")]
    [InlineData(true, "returned null")]
    public async Task A_credential_that_is_not_copied_is_named_in_the_critical_log(bool returnsNull, string problem)
    {
        var logger = new CapturingLogger();
        var resolver = new ValidatedClientResolver(
            new SingleClientRepository(ConfidentialClient(new FirstCallUncopiedCredential(returnsNull))),
            new PassingValidator(),
            logger);

        await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical)
            .Which.Message.Should().Contain("FirstCallUncopiedCredential").And.Contain(problem);
    }

    [Fact]
    public async Task A_configuration_failure_thrown_by_a_credential_s_Snapshot_is_logged_by_its_type_only()
    {
        // Only a failure the snapshot raised itself is logged by name. A ZeeKayDaConfigurationException
        // thrown by the credential is the credential's text, which may carry its data.
        var logger = new CapturingLogger();
        var credential = new ThrowingSnapshotCredential(new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("custom.credential.unreadable", "Cannot copy salt=0badc0de.")));
        var resolver = new ValidatedClientResolver(
            new SingleClientRepository(ConfidentialClient(credential)), new PassingValidator(), logger);

        var result = await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

        result.Should().BeNull();
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical)
            .Which.Message.Should().Contain(nameof(ZeeKayDaConfigurationException)).And.NotContain("0badc0de");
    }

    [Fact]
    public async Task A_null_credential_is_served_as_unknown_and_named_in_the_critical_log()
    {
        var logger = new CapturingLogger();
        var resolver = new ValidatedClientResolver(
            new SingleClientRepository(Client() with { Credentials = [null!] }), new PassingValidator(), logger);

        var result = await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

        result.Should().BeNull();
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical)
            .Which.Message.Should().Contain("null entry in Credentials");
    }

    [Fact]
    public async Task A_secret_whose_Snapshot_is_not_a_secret_is_served_as_unknown()
    {
        // Served, the client would hold no secret and fail every authentication as a wrong secret,
        // with nothing in the log to say why.
        var resolver = Resolver(Client() with { Credentials = [new DemotingSecret()] }, new PassingValidator());

        var result = await resolver.FindByClientIdAsync("client-1", TestContext.Current.CancellationToken);

        result.Should().BeNull();
    }

    // ── Fixture ───────────────────────────────────────────────────────────────────────────────

    private static ClientRegistration Client() =>
        ClientRegistration.CreatePublic(
            "client-1",
            redirectUris: ["https://app.example.com/callback"],
            postLogoutRedirectUris: [],
            allowedScopes: ["openid"]);

    private static ClientRegistration ConfidentialClient(IClientCredential credential, string clientId = "client-1") =>
        ClientRegistration.CreateConfidential(
            clientId,
            credential,
            redirectUris: ["https://app.example.com/callback"],
            postLogoutRedirectUris: [],
            allowedScopes: ["openid"]);

    private static ValidatedClientResolver Resolver(
        IClientRegistration client, IClientRegistrationValidator validator) =>
        new(new SingleClientRepository(client), validator, NullLogger());

    private static ISanitizingLogger<ValidatedClientResolver> NullLogger() => new CapturingLogger();

    private sealed class SingleClientRepository(IClientRegistration client) : IClientRepository
    {
        public ValueTask<IClientRegistration?> FindByClientIdAsync(
            string clientId, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<IClientRegistration?>(
                string.Equals(clientId, client.ClientId, StringComparison.Ordinal) ? client : null);
    }

    private sealed class MultiClientRepository(params IClientRegistration[] clients) : IClientRepository
    {
        public ValueTask<IClientRegistration?> FindByClientIdAsync(
            string clientId, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(
                clients.FirstOrDefault(c => string.Equals(c.ClientId, clientId, StringComparison.Ordinal)));
    }

    private sealed class MutableRepository(IClientRegistration current) : IClientRepository
    {
        public IClientRegistration Current { get; set; } = current;

        public ValueTask<IClientRegistration?> FindByClientIdAsync(
            string clientId, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<IClientRegistration?>(Current);
    }

    private sealed class ThrowingRepository : IClientRepository
    {
        public ValueTask<IClientRegistration?> FindByClientIdAsync(
            string clientId, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<IClientRegistration?>(new ThrowingRegistration());
    }

    private sealed class ThrowingRegistration : IClientRegistration
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

        public IReadOnlyList<IClientCredential> Credentials => [];
    }

    private sealed class FreshInstanceRepository : IClientRepository
    {
        public ValueTask<IClientRegistration?> FindByClientIdAsync(
            string clientId, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<IClientRegistration?>(Client());
    }

    /// <summary>
    /// Returns itself, or <see langword="null"/>, from its first <c>Snapshot()</c> and a real copy
    /// from every later one.
    /// </summary>
    private sealed class FirstCallUncopiedCredential(bool returnsNull) : IClientCredential
    {
        private int _calls;

        public IClientCredential Snapshot()
        {
            if (Interlocked.Increment(ref _calls) > 1)
                return new FirstCallUncopiedCredential(returnsNull);

            return returnsNull ? null! : this;
        }
    }

    private sealed class ThrowingSnapshotCredential(Exception exception) : IClientCredential
    {
        public IClientCredential Snapshot() => throw exception;
    }

    private sealed class CopyingCredential : IClientCredential
    {
        public IClientCredential Snapshot() => new CopyingCredential();
    }

    private sealed class DemotingSecret : IClientSecret
    {
        public IClientCredential Snapshot() => new CopyingCredential();
    }

    private sealed class PassingValidator : IClientRegistrationValidator
    {
        public void Validate(IClientRegistration client)
        {
        }
    }

    private sealed class RejectingValidator : IClientRegistrationValidator
    {
        public void Validate(IClientRegistration client) =>
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure("test_rule", "Deliberately rejected by the test."));
    }

    /// <summary>Rejects every registration, for the rule this test named for its <c>client_id</c>.</summary>
    private sealed class CodePerClientValidator(IReadOnlyDictionary<string, string> codesByClientId)
        : IClientRegistrationValidator
    {
        public void Validate(IClientRegistration client) =>
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    codesByClientId[client.ClientId], "Deliberately rejected by the test."));
    }

    /// <summary>Rejects every registration, breaking a different rule each time.</summary>
    private sealed class DifferentRuleEachTimeValidator : IClientRegistrationValidator
    {
        private int _calls;

        public void Validate(IClientRegistration client)
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

        public void Validate(IClientRegistration client) =>
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

        public void Validate(IClientRegistration client)
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

        public void Validate(IClientRegistration client)
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

        public void Validate(IClientRegistration client) => Calls++;
    }

    private sealed class CapturingLogger : ISanitizingLogger<ValidatedClientResolver>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }
}
