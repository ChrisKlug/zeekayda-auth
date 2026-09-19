using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Tests.Interaction;
using ZeeKayDa.Auth.AspNetCore.Tests.Providers;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// One ASP.NET Core host per configuration, shared by every test needing the real request path:
/// routing, the issuer-host constraint, the endpoint group's conventions, and the middleware
/// pipeline. Behaviour a handler produces on its own belongs in a host-free
/// <see cref="EndpointHost"/> test instead.
/// </summary>
/// <remarks>
/// <para>
/// The host is built on first use rather than in the constructor, so a test class naming several of
/// these as class fixtures pays only for the hosts its own tests actually reach.
/// </para>
/// <para>
/// Taken as an <c>IClassFixture</c>, never a collection fixture. A collection is xUnit's unit of
/// parallelism, so sharing one host across classes would serialise those classes against each other —
/// which costs more wall time than the host boots it saves. One host per class keeps the classes
/// parallel, and the tests within a class were always sequential anyway.
/// </para>
/// </remarks>
public abstract class SharedHostFixture : IDisposable
{
    private readonly Lock _gate = new();
    private readonly List<HttpClient> _clients = [];

    private WebApplicationFactory<TestWebAppFactory>? _factory;

    /// <summary>A client addressing the host at <see cref="DefaultBaseAddress"/>.</summary>
    public HttpClient Client => ClientFor(DefaultBaseAddress);

    /// <summary>The host's services, for reading a registered option or store.</summary>
    public IServiceProvider Services => Factory.Services;

    /// <summary>The address this host answers as — its configured issuer.</summary>
    protected abstract string DefaultBaseAddress { get; }

    /// <summary>
    /// This fixture's host, built on first access. Available to a derived fixture so it never needs
    /// to keep a second reference to the factory it returned from <see cref="CreateFactory"/>.
    /// </summary>
    protected WebApplicationFactory<TestWebAppFactory> Factory
    {
        get
        {
            lock (_gate)
                return _factory ??= CreateFactory();
        }
    }

    /// <summary>
    /// A client addressing the host at <paramref name="baseAddress"/>, for the tests that prove a
    /// request on the wrong host or the wrong scheme is refused. Clients are reused per address.
    /// </summary>
    /// <param name="baseAddress">The base address the client should send to.</param>
    /// <returns>A client bound to <paramref name="baseAddress"/>.</returns>
    public HttpClient ClientFor(string baseAddress)
    {
        ArgumentNullException.ThrowIfNull(baseAddress);

        var factory = Factory;

        lock (_gate)
        {
            var existing = _clients.Find(
                c => c.BaseAddress?.ToString().TrimEnd('/') == baseAddress.TrimEnd('/'));

            if (existing is not null)
                return existing;

            var client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri(baseAddress),
            });

            _clients.Add(client);
            return client;
        }
    }

    /// <summary>
    /// A client of its own for one test, never reused — so a session cookie one test establishes
    /// cannot silently sign the next one in, the way a client shared through <see cref="ClientFor"/>
    /// would.
    /// </summary>
    /// <param name="configure">
    /// Adjusts the client's options. <c>AllowAutoRedirect</c> and <c>HandleCookies</c> both default to
    /// <see langword="true"/>, so a test asserting on an unfollowed 3xx, or sending a hand-built
    /// <c>Cookie</c> header, turns the relevant one off here.
    /// </param>
    /// <returns>A fresh client. The fixture disposes it.</returns>
    public HttpClient NewClient(Action<WebApplicationFactoryClientOptions>? configure = null)
    {
        var factory = Factory;

        var options = new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(DefaultBaseAddress),
        };

        configure?.Invoke(options);

        var client = factory.CreateClient(options);

        lock (_gate)
            _clients.Add(client);

        return client;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        foreach (var client in _clients)
            client.Dispose();

        _factory?.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>Builds this fixture's host. Called once, on first use.</summary>
    /// <returns>The factory whose host the fixture's tests run against.</returns>
    protected abstract WebApplicationFactory<TestWebAppFactory> CreateFactory();
}

/// <summary>The default test configuration: issuer <c>https://test.example.com</c>.</summary>
public sealed class DefaultHostFixture : SharedHostFixture
{
    /// <inheritdoc/>
    protected override string DefaultBaseAddress => "https://test.example.com";

    /// <inheritdoc/>
    protected override WebApplicationFactory<TestWebAppFactory> CreateFactory() => new TestWebAppFactory();
}

/// <summary>
/// A path-bearing issuer, <c>https://test.example.com/tenant1</c> — the configuration that proves
/// discovery registers under the issuer's path, as OIDC Discovery 1.0 §4.1 and RFC 9207 §4 require.
/// </summary>
public sealed class TenantIssuerHostFixture : SharedHostFixture
{
    /// <summary>The issuer this host is configured with, path included.</summary>
    public const string Issuer = "https://test.example.com/tenant1";

    /// <inheritdoc/>
    protected override string DefaultBaseAddress => "https://test.example.com";

    /// <inheritdoc/>
    protected override WebApplicationFactory<TestWebAppFactory> CreateFactory()
        => new TestWebAppFactory(opts => opts.Issuer = Issuer);
}

/// <summary>
/// A host whose authorization <c>FallbackPolicy</c> requires an authenticated user, for proving the
/// public metadata endpoints stay anonymously readable.
/// </summary>
public sealed class FallbackPolicyHostFixture : SharedHostFixture
{
    /// <inheritdoc/>
    protected override string DefaultBaseAddress => "https://test.example.com";

    /// <inheritdoc/>
    protected override WebApplicationFactory<TestWebAppFactory> CreateFactory()
        => new TestWebAppFactoryWithFallbackAuthorizationPolicy();
}

/// <summary>
/// A loopback host with <c>AllowInsecureIssuer</c>, issuer <c>http://localhost:5000</c>, for the
/// tests that prove plain HTTP is served to loopback and refused to anything else.
/// </summary>
public sealed class LoopbackHostFixture : SharedHostFixture
{
    /// <inheritdoc/>
    protected override string DefaultBaseAddress => "http://localhost:5000";

    /// <inheritdoc/>
    protected override WebApplicationFactory<TestWebAppFactory> CreateFactory()
        => new TestWebAppFactoryWithRemoteIp(IPAddress.Loopback);
}

/// <summary>
/// A host shared across one test class whose tests drive a full request flow — login, consent, a code
/// exchange — together with the mutable test doubles that host was built with: a clock the tests move
/// and a log they read.
/// </summary>
/// <remarks>
/// <para>
/// One host per class rather than one per test. xUnit runs the tests within a class sequentially, so
/// nothing here has to be safe against a concurrent sibling — only against what the previous test
/// left behind. <see cref="Reset"/> is what clears that, and the test class calls it from its own
/// constructor, which xUnit runs once per test.
/// </para>
/// <para>
/// A test whose flow depends on its own cookies takes <see cref="SharedHostFixture.NewClient"/>, not
/// <see cref="SharedHostFixture.Client"/> — a shared client would carry a session cookie from one test
/// into the next and sign it in silently. A test needing a different configuration, or one asserting
/// that a store is empty, still builds its own host.
/// </para>
/// </remarks>
public abstract class FlowHostFixture : SharedHostFixture
{
    /// <summary>The instant every test in the class starts from.</summary>
    protected abstract DateTimeOffset StartTime { get; }

    /// <summary>The clock the host runs on, for a test that needs time to pass.</summary>
    public FakeTimeProvider Time => _time ??= new FakeTimeProvider(StartTime);

    /// <summary>
    /// What the host resolves as its <see cref="TimeProvider"/>: a shim that forwards to whichever
    /// <see cref="FakeTimeProvider"/> is current. The host is built once, but
    /// <see cref="FakeTimeProvider.SetUtcNow"/> refuses to move backwards, so <see cref="Reset"/>
    /// cannot rewind the clock a previous test advanced — it replaces it, and the shim is how the
    /// already-built host sees the replacement.
    /// </summary>
    private TimeProvider HostClock => _hostClock ??= new ForwardingTimeProvider(() => Time);

    /// <summary>What the host has logged.</summary>
    public CapturingLoggerProvider Logs { get; } = new();

    private FakeTimeProvider? _time;
    private TimeProvider? _hostClock;

    /// <summary>
    /// Returns the clock to <see cref="StartTime"/> and discards captured log entries, so a test does
    /// not inherit them from the test that ran before it.
    /// </summary>
    public virtual void Reset()
    {
        _time = new FakeTimeProvider(StartTime);
        Logs.Clear();
    }

    /// <summary>
    /// A client for a test that drives a redirect-carrying flow: its own cookie jar, and redirects
    /// left unfollowed so the test can assert on the 3xx it gets.
    /// </summary>
    /// <param name="handleCookies">
    /// Whether the client keeps a cookie jar. Turn it off to send a hand-built <c>Cookie</c> header.
    /// </param>
    /// <returns>A fresh client. The fixture disposes it.</returns>
    public HttpClient NewFlowClient(bool handleCookies = true)
        => NewClient(options =>
        {
            options.AllowAutoRedirect = false;
            options.HandleCookies = handleCookies;
        });

    /// <summary>
    /// Registers the shared clock and log capture. A fixture's <see cref="SharedHostFixture.CreateFactory"/>
    /// passes this as the host's <c>configureBuilder</c>, chaining its own registrations after it.
    /// </summary>
    /// <param name="builder">The builder the host is being configured through.</param>
    /// <param name="fakeClock">
    /// Whether the host runs on <see cref="Time"/> rather than the real clock. Pass
    /// <see langword="false"/> for a host whose flow goes through ASP.NET Core's own authentication
    /// handlers: their correlation cookies and data-protection payloads are stamped against the real
    /// clock, and a host reading a fake one rejects its own callback. <see cref="Time"/> means nothing
    /// on such a host, and a test there that needs to control time registers its own clock and takes
    /// its own host.
    /// </param>
    protected void AddTestDoubles(ZeeKayDaAuthBuilder builder, bool fakeClock = true)
    {
        ArgumentNullException.ThrowIfNull(builder);

        if (fakeClock)
            builder.Services.AddSingleton(HostClock);
        builder.Services.AddLogging(logging => logging.AddProvider(Logs));
    }

    /// <summary>Forwards every call to the clock the fixture currently holds.</summary>
    private sealed class ForwardingTimeProvider(Func<TimeProvider> current) : TimeProvider
    {
        public override TimeZoneInfo LocalTimeZone => current().LocalTimeZone;

        public override long TimestampFrequency => current().TimestampFrequency;

        public override DateTimeOffset GetUtcNow() => current().GetUtcNow();

        public override long GetTimestamp() => current().GetTimestamp();

        public override ITimer CreateTimer(
            TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
            => current().CreateTimer(callback, state, dueTime, period);
    }
}

/// <summary>
/// The single acme-only provider host shared by every <c>ProviderRoundTripTests</c> case that
/// registers no provider, option or client behaviour of its own: the challenge, the callback,
/// the return through resume, every refusal at the provider, and every failure the callback
/// endpoint itself can report.
/// </summary>
/// <remarks>
/// A provider challenge hands the browser off to <c>https://acme.example.net</c> — a host outside
/// this app the test never runs a request against, because the round trip's assertions read the
/// challenge, callback and resume responses one hop at a time rather than following where they
/// point. <see cref="NewFlowClient"/> is what a round-trip test takes instead of the inherited
/// <see cref="SharedHostFixture.NewClient"/>, and <see cref="NewClientWithoutCookies"/> covers the
/// tests proving a stray or cross-browser request without the binding cookie is refused.
/// </remarks>
public sealed class ProviderRoundTripHostFixture : FlowHostFixture
{

    /// <inheritdoc/>
    protected override DateTimeOffset StartTime => new(2026, 9, 19, 12, 0, 0, TimeSpan.Zero);

    /// <inheritdoc/>
    protected override string DefaultBaseAddress => "https://test.example.com";

    /// <inheritdoc/>
    protected override WebApplicationFactory<TestWebAppFactory> CreateFactory()
        => new TestWebAppFactory(
            configureBuilder: builder =>
            {
                AddTestDoubles(builder, fakeClock: false);
                builder.WithProviders(auth => auth.AddOAuth("acme", "Acme", Providers.ProviderTestHost.ConfigureAcme));
            },
            mapEndpoints: Providers.ProviderTestHost.MapHostPages);

}

/// <summary>
/// The same acme-only provider host as <see cref="ProviderRoundTripHostFixture"/>, configured
/// under the path-based issuer <c>https://test.example.com/tenant1</c> — shared by the theory
/// proving a callback or resume route answers 404 when the request path differs from the mapped
/// route only in case or a trailing slash. Every row is a read against the same mapped and
/// wrong paths, so nothing here mutates state a later row could see.
/// </summary>
public sealed class ProviderRoundTripTenantHostFixture : FlowHostFixture
{

    /// <inheritdoc/>
    protected override DateTimeOffset StartTime => new(2026, 9, 19, 13, 0, 0, TimeSpan.Zero);

    /// <inheritdoc/>
    protected override string DefaultBaseAddress => "https://test.example.com";

    /// <inheritdoc/>
    protected override WebApplicationFactory<TestWebAppFactory> CreateFactory()
        => new TestWebAppFactory(
            configureOptions: options => options.Issuer = "https://test.example.com/tenant1",
            configureBuilder: builder =>
            {
                AddTestDoubles(builder, fakeClock: false);
                builder.WithProviders(auth => auth.AddOAuth("acme", "Acme", Providers.ProviderTestHost.ConfigureAcme));
            },
            mapEndpoints: Providers.ProviderTestHost.MapHostPages);

    /// <summary>
    /// A client with redirects surfaced rather than followed, matching the raw client the theory
    /// this fixture serves used to build for itself directly.
    /// </summary>
    /// <returns>A fresh client, addressed at <see cref="DefaultBaseAddress"/>. The caller disposes it.</returns>
}

/// <summary>
/// The host shared by <see cref="LoginInteractionTests"/>: the login page it maps, on a clock
/// starting where that class's tests have always assumed it starts.
/// </summary>
public sealed class LoginInteractionHostFixture : FlowHostFixture
{
    /// <inheritdoc/>
    protected override DateTimeOffset StartTime => new(2026, 8, 29, 12, 0, 0, TimeSpan.Zero);

    /// <inheritdoc/>
    protected override string DefaultBaseAddress => "https://test.example.com";

    /// <inheritdoc/>
    protected override WebApplicationFactory<TestWebAppFactory> CreateFactory()
        => new TestWebAppFactory(
            configureBuilder: builder => AddTestDoubles(builder),
            mapEndpoints: LoginInteractionTests.MapHostPages);

    /// <summary>
    /// A client that does not follow redirects and keeps its own cookie jar — this class's tests
    /// read a redirect response itself (status, <c>Location</c>, the absence of a header) rather
    /// than the page it points to, so the base <see cref="NewClient"/>'s default
    /// <c>WebApplicationFactoryClientOptions</c>, which follows redirects, would answer with the
    /// followed page instead of the response under test.
    /// </summary>
    /// <returns>A fresh client, addressed at <see cref="DefaultBaseAddress"/>. The caller disposes it.</returns>
}

/// <summary>
/// The host shared by <see cref="AuthorizationCodeIssuanceTests"/>: the default issuer, the three
/// clients that class registers, and the login and consent pages it maps.
/// </summary>
public sealed class AuthorizationCodeIssuanceHostFixture : FlowHostFixture
{
    /// <inheritdoc/>
    protected override DateTimeOffset StartTime => new(2026, 9, 5, 12, 0, 0, TimeSpan.Zero);

    /// <inheritdoc/>
    protected override string DefaultBaseAddress => "https://test.example.com";

    /// <inheritdoc/>
    protected override WebApplicationFactory<TestWebAppFactory> CreateFactory()
        => new TestWebAppFactory(
            configureBuilder: builder =>
            {
                AddTestDoubles(builder);
                builder.AddInMemoryClients(clients => clients
                    .Add(AuthorizationCodeIssuanceTests.ConsentingRegistration())
                    .Add(AuthorizationCodeIssuanceTests.TrustedRegistration())
                    .AddPublic(
                        AuthorizationCodeIssuanceTests.OtherClient,
                        ["https://other.example.com/callback"],
                        [],
                        ["openid"]));
            },
            mapEndpoints: AuthorizationCodeIssuanceTests.MapHostPages);
}

/// <summary>
/// The host shared by <see cref="ConsentInteractionTests"/>: the default issuer, the consenting and
/// trusted clients that class registers, and the login and consent pages it maps.
/// </summary>
public sealed class ConsentInteractionHostFixture : FlowHostFixture
{
    /// <inheritdoc/>
    protected override DateTimeOffset StartTime => new(2026, 9, 5, 12, 0, 0, TimeSpan.Zero);

    /// <inheritdoc/>
    protected override string DefaultBaseAddress => "https://test.example.com";

    /// <inheritdoc/>
    protected override WebApplicationFactory<TestWebAppFactory> CreateFactory()
        => new TestWebAppFactory(
            configureOptions: options => options.AuthorizationEndpoint.Interaction.ConsentPath = FlowAssertions.ConsentPath,
            configureBuilder: builder =>
            {
                AddTestDoubles(builder);
                builder.AddInMemoryClients(clients => clients
                    .Add(ConsentInteractionTests.ConsentingRegistration())
                    .Add(ConsentInteractionTests.TrustedRegistration()));
            },
            mapEndpoints: ConsentInteractionTests.MapHostPages);
}

/// <summary>
/// The host shared by <see cref="NothingToContinueTests"/>: the default issuer, the restarting,
/// plain and trusted clients that class registers, and the login, consent, logout and error pages
/// it maps.
/// </summary>
public sealed class NothingToContinueHostFixture : FlowHostFixture
{
    /// <inheritdoc/>
    protected override DateTimeOffset StartTime => new(2026, 9, 17, 12, 0, 0, TimeSpan.Zero);

    /// <inheritdoc/>
    protected override string DefaultBaseAddress => "https://test.example.com";

    /// <inheritdoc/>
    protected override WebApplicationFactory<TestWebAppFactory> CreateFactory()
        => new TestWebAppFactory(
            configureOptions: options =>
            {
                options.AuthorizationEndpoint.Interaction.ErrorPath = null;
                options.EndSessionEndpoint.LogoutPath = NothingToContinueTests.LogoutPath;
            },
            configureBuilder: builder =>
            {
                AddTestDoubles(builder);
                builder.AddInMemoryClients(clients => clients
                    .Add(NothingToContinueTests.RestartingRegistration())
                    .Add(NothingToContinueTests.PlainRegistration())
                    .Add(NothingToContinueTests.TrustedRegistration()));
            },
            mapEndpoints: NothingToContinueTests.MapHostPages);
}

/// <summary>
/// The host shared by <see cref="ProviderSignInEventTests"/>: one working <c>acme</c> OAuth
/// provider and the host's own pages, with <see cref="OnProviderSignIn"/> forwarding to whatever
/// delegate the current test set — the one piece of configuration those tests vary per test.
/// </summary>
/// <remarks>
/// A test that instead needs its own <c>configureAcme</c>, its own <see cref="TimeProvider"/>, its
/// own interaction backing store, or endpoints beyond <see cref="ProviderTestHost.MapHostPages"/>
/// keeps its own host, because those are baked into the host at registration and this fixture
/// registers only one shape of each.
/// </remarks>
public sealed class ProviderSignInHostFixture : FlowHostFixture
{
    /// <summary>What OnProviderSignIn does for the current test. Each test sets this while arranging.</summary>
    public Func<ProviderSignInContext, Task>? OnProviderSignIn { get; set; }

    /// <inheritdoc/>
    protected override DateTimeOffset StartTime => new(2026, 9, 19, 12, 0, 0, TimeSpan.Zero);

    /// <inheritdoc/>
    protected override string DefaultBaseAddress => "https://test.example.com";

    /// <inheritdoc/>
    protected override WebApplicationFactory<TestWebAppFactory> CreateFactory()
        => new TestWebAppFactory(
            configureBuilder: builder =>
            {
                AddTestDoubles(builder, fakeClock: false);
                builder.WithProviders(
                    auth => auth.AddOAuth("acme", "Acme", ProviderTestHost.ConfigureAcme),
                    // Forwards to whatever the current test set, so one host serves every callback.
                    options => options.OnProviderSignIn = context => OnProviderSignIn?.Invoke(context) ?? Task.CompletedTask);
            },
            mapEndpoints: ProviderTestHost.MapHostPages);

    /// <summary>
    /// A client that does not follow redirects and keeps its own cookie jar — this class's tests
    /// read a redirect response itself (status, <c>Location</c>, cookies) and the query parameters
    /// a relative <c>Location</c> carries, so the base <see cref="SharedHostFixture.NewClient"/>'s
    /// default <c>WebApplicationFactoryClientOptions</c>, which follows redirects, would answer with
    /// the followed page instead of the response under test.
    /// </summary>
    /// <param name="baseAddress">The base address the client should send to, defaulting to this host's.</param>
    /// <returns>A fresh client. The caller disposes it.</returns>

    /// <summary>
    /// Returns the clock and log to their starting state and clears <see cref="OnProviderSignIn"/>,
    /// so a test that sets no callback does not inherit the previous test's.
    /// </summary>
    public override void Reset()
    {
        base.Reset();
        OnProviderSignIn = null;
    }
}
