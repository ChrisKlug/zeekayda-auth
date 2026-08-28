using FluentAssertions;
using Microsoft.Extensions.Logging;
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

        result.Should().BeSameAs(client);
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

    // ── Fixture ───────────────────────────────────────────────────────────────────────────────

    private static ClientRegistration Client() =>
        ClientRegistration.CreatePublic(
            "client-1",
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

    private sealed class MutableRepository(IClientRegistration current) : IClientRepository
    {
        public IClientRegistration Current { get; set; } = current;

        public ValueTask<IClientRegistration?> FindByClientIdAsync(
            string clientId, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<IClientRegistration?>(Current);
    }

    private sealed class FreshInstanceRepository : IClientRepository
    {
        public ValueTask<IClientRegistration?> FindByClientIdAsync(
            string clientId, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<IClientRegistration?>(Client());
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
