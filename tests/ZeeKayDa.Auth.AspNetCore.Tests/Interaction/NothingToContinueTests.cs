using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// A page submitted, or read, for an interaction the browser no longer has — a double submit, a
/// page left open too long, a bookmarked page, another browser — is answered by the framework:
/// back to the client to start again when it can be, and to the error page otherwise.
/// </summary>
public sealed class NothingToContinueTests : IDisposable
{
    private const string Issuer = "https://test.example.com";
    private const string RegisteredRedirect = "https://test.example.com/callback";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string LoginPath = "/account/login";
    private const string ConsentPath = FlowAssertions.ConsentPath;
    private const string LogoutPath = "/account/logout";
    private const string ErrorPath = "/auth-error";
    private const string RestartingClient = "restarting-client";
    private const string PlainClient = "plain-client";
    private const string TrustedClient = "trusted-client";
    private const string InitiateLoginUri = "https://app.example.com/start?from=idp";

    private static readonly DateTimeOffset Now = new(2026, 9, 17, 12, 0, 0, TimeSpan.Zero);

    private readonly FakeTimeProvider _time = new(Now);
    private readonly CapturingLoggerProvider _logs = new();
    private readonly TestWebAppFactory _factory;
    private readonly HttpClient _client;

    public NothingToContinueTests()
    {
        _factory = NewFactory();
        _client = NewClient(_factory);
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    // ── Back to the client ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_consent_submitted_twice_sends_the_browser_to_the_clients_initiate_login_uri()
    {
        var interactionId = await ReachConsentAsync(RestartingClient);
        (await GrantAsync(interactionId)).ShouldHaveIssuedCodeTo(RegisteredRedirect);

        using var again = await GrantAsync(interactionId);

        again.ShouldRestartAtTheClient();
    }

    [Fact]
    public async Task A_login_submitted_after_the_interaction_expired_sends_the_browser_to_the_clients_initiate_login_uri()
    {
        var interactionId = InteractionIdFrom(await AuthorizeAsync(RestartingClient));
        _time.Advance(AuthorizationRequestContextStore.Lifetime + TimeSpan.FromMinutes(1));

        using var signIn = await PostLoginAsync(interactionId);

        signIn.ShouldRestartAtTheClient();
    }

    [Fact]
    public async Task A_denial_submitted_after_a_grant_sends_the_browser_to_the_client_without_telling_it_access_denied()
    {
        // The grant stands; the late Deny must not reach the client as an error for a request it
        // already has a code for.
        var interactionId = await ReachConsentAsync(RestartingClient);
        (await GrantAsync(interactionId)).ShouldHaveIssuedCodeTo(RegisteredRedirect);

        using var deny = await PostFormAsync(WithInteractionId(ConsentPath, interactionId), ("action", "deny"));

        deny.ShouldRestartAtTheClient();
    }

    [Fact]
    public async Task The_restart_carries_nothing_from_the_request()
    {
        // The destination and its only added parameter come from the registration and the
        // configuration. A request stuffing its own iss, or a return address, changes nothing.
        var interactionId = await ReachConsentAsync(RestartingClient);
        (await GrantAsync(interactionId)).ShouldHaveIssuedCodeTo(RegisteredRedirect);
        var url = QueryHelpers.AddQueryString(WithInteractionId(ConsentPath, interactionId), new Dictionary<string, string?>
        {
            ["iss"] = "https://attacker.example.net",
            ["target_link_uri"] = "https://attacker.example.net/collect",
        });

        using var again = await PostFormAsync(url, ("scope", "openid"), ("iss", "https://attacker.example.net"));

        again.ShouldRestartAtTheClient();
    }

    // ── Not back to the client ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_client_without_an_initiate_login_uri_gets_the_error_page()
    {
        var interactionId = await ReachConsentAsync(PlainClient);
        (await GrantAsync(interactionId)).ShouldHaveIssuedCodeTo(RegisteredRedirect);

        using var again = await GrantAsync(interactionId);

        await again.ShouldHaveFoundNothingToContinueAsync();
    }

    [Fact]
    public async Task The_host_error_page_is_told_the_error_is_nothing_to_continue()
    {
        using var factory = NewFactory(errorPath: ErrorPath);
        using var client = NewClient(factory);
        var interactionId = InteractionIdFrom(await AuthorizeAsync(PlainClient, client));
        _time.Advance(AuthorizationRequestContextStore.Lifetime + TimeSpan.FromMinutes(1));

        using var signIn = await PostLoginAsync(interactionId, client);

        signIn.StatusCode.Should().Be(HttpStatusCode.Redirect);
        signIn.Headers.Location!.OriginalString.Should().StartWith($"{ErrorPath}?error_id=");
        var error = await ReadJsonAsync(client, signIn.Headers.Location.OriginalString);
        error.GetProperty("kind").GetString().Should().Be(nameof(AuthorizationErrorKind.NothingToContinue));
        error.GetProperty("error").GetString().Should().Be(NothingToContinue.ErrorCode);
    }

    [Fact]
    public async Task A_page_submitted_from_another_browser_is_not_sent_to_the_client()
    {
        // The browser that learned the identifier from a leaked URL holds no binding, so nothing
        // names the client for it: it gets the error page, never the client's restart.
        var interactionId = InteractionIdFrom(await AuthorizeAsync(RestartingClient));
        using var otherBrowser = NewClient(_factory);

        using var signIn = await PostLoginAsync(interactionId, otherBrowser);

        await signIn.ShouldHaveFoundNothingToContinueAsync();
    }

    [Fact]
    public async Task A_client_removed_since_the_interaction_is_not_sent_the_browser()
    {
        var repository = new MutableClientRepository(RestartingRegistration());
        using var factory = NewFactory(repository: repository);
        using var client = NewClient(factory);
        var interactionId = InteractionIdFrom(await AuthorizeAsync(RestartingClient, client));
        _time.Advance(AuthorizationRequestContextStore.Lifetime + TimeSpan.FromMinutes(1));

        repository.Current = null;
        using var signIn = await PostLoginAsync(interactionId, client);

        await signIn.ShouldHaveFoundNothingToContinueAsync("a registration that no longer answers vouches for no destination");
    }

    [Fact]
    public async Task A_client_that_changed_its_initiate_login_uri_is_sent_the_browser_at_the_new_one()
    {
        // Read from the registration at the point of use, never remembered from the interaction.
        var repository = new MutableClientRepository(RestartingRegistration());
        using var factory = NewFactory(repository: repository);
        using var client = NewClient(factory);
        var interactionId = InteractionIdFrom(await AuthorizeAsync(RestartingClient, client));
        _time.Advance(AuthorizationRequestContextStore.Lifetime + TimeSpan.FromMinutes(1));

        repository.Current = RestartingRegistration() with { InitiateLoginUri = "https://app.example.com/moved" };
        using var signIn = await PostLoginAsync(interactionId, client);

        signIn.Headers.Location!.OriginalString.Should().StartWith("https://app.example.com/moved?iss=");
    }

    [Fact]
    public async Task A_login_submitted_without_an_interaction_id_gets_the_error_page_and_a_warning()
    {
        // A bookmarked login page, or a form that drops zkd_i: the log is where the second shows.
        using var signIn = await PostLoginAsync(interactionId: null);

        await signIn.ShouldHaveFoundNothingToContinueAsync();
        _logs.Entries.Should().Contain(entry =>
            entry.Level == LogLevel.Warning && entry.Message.Contains("without the 'zkd_i' parameter", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_login_submitted_for_an_expired_interaction_is_logged_as_information_only()
    {
        var interactionId = InteractionIdFrom(await AuthorizeAsync(PlainClient));
        _time.Advance(AuthorizationRequestContextStore.Lifetime + TimeSpan.FromMinutes(1));

        using var signIn = await PostLoginAsync(interactionId);

        await signIn.ShouldHaveFoundNothingToContinueAsync();
        var entry = _logs.Entries.Single(entry => entry.Message.Contains("page was reached", StringComparison.Ordinal));
        entry.Level.Should().Be(LogLevel.Information);
        entry.Message.Should().Contain(nameof(NothingToContinueReason.NotFound));
    }

    // ── Pages that only read ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_consent_page_with_nothing_to_ask_reads_null()
    {
        var interactionId = await ReachConsentAsync(PlainClient);
        (await GrantAsync(interactionId)).ShouldHaveIssuedCodeTo(RegisteredRedirect);

        var page = await ReadJsonAsync(_client, WithInteractionId(ConsentPath, interactionId));

        page.GetProperty("found").GetBoolean().Should().BeFalse();
    }

    [Fact]
    public async Task A_consent_page_reached_without_an_interaction_id_reads_null_and_warns()
    {
        var page = await ReadJsonAsync(_client, ConsentPath);

        page.GetProperty("found").GetBoolean().Should().BeFalse();
        _logs.Entries.Should().Contain(entry => entry.Level == LogLevel.Warning && entry.Message.Contains("consent", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_logout_page_with_nothing_to_confirm_reads_null()
    {
        await SignInAsync();
        var asked = await _client.GetAsync("/connect/endsession", Cancellation);
        _time.Advance(LogoutRequestStore.Lifetime);

        var page = await ReadJsonAsync(_client, asked.Headers.Location!.OriginalString);

        page.GetProperty("found").GetBoolean().Should().BeFalse();
    }

    [Fact]
    public async Task A_logout_page_with_a_sign_out_to_confirm_reads_it()
    {
        await SignInAsync();
        var asked = await _client.GetAsync("/connect/endsession", Cancellation);

        var page = await ReadJsonAsync(_client, asked.Headers.Location!.OriginalString);

        page.GetProperty("subject").GetString().Should().Be("user-1");
    }

    // ── Host ──────────────────────────────────────────────────────────────────────────────────

    private TestWebAppFactory NewFactory(string? errorPath = null, IClientRepository? repository = null) => new(
        configureOptions: options =>
        {
            options.AuthorizationEndpoint.Interaction.ErrorPath = errorPath;
            options.EndSessionEndpoint.LogoutPath = LogoutPath;
        },
        configureBuilder: builder =>
        {
            builder.Services.AddSingleton<TimeProvider>(_time);
            builder.Services.AddLogging(logging => logging.AddProvider(_logs));
            builder.AddInMemoryClients(clients => clients
                .Add(RestartingRegistration())
                .Add(ClientRegistration.CreatePublic(PlainClient, [RegisteredRedirect], [], ["openid"]))
                .Add(ClientRegistration.CreatePublic(TrustedClient, [RegisteredRedirect], [], ["openid"]) with { RequireConsent = false }));

            if (repository is not null)
                builder.Services.AddSingleton(repository);
        },
        mapEndpoints: MapHostPages);

    private static ClientRegistration RestartingRegistration() =>
        ClientRegistration.CreatePublic(RestartingClient, [RegisteredRedirect], [], ["openid"]) with
        {
            InitiateLoginUri = InitiateLoginUri,
        };

    /// <summary>The host's pages, written as a host that renders its own "nothing here" would write them.</summary>
    private static void MapHostPages(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost(LoginPath, (ILoginInteraction login) => login.SignInAsync(
            new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-1")], "test")),
            AuthenticationMethods.Password));

        endpoints.MapGet(ConsentPath, async (HttpContext context, IConsentInteraction consent) =>
        {
            var request = await consent.TryGetRequestAsync(context.RequestAborted);
            return Results.Json(new { found = request is not null, clientId = request?.Client.ClientId });
        });

        endpoints.MapPost(ConsentPath, async (HttpContext context, IConsentInteraction consent) =>
        {
            var form = await context.Request.ReadFormAsync(context.RequestAborted);

            if (form["action"].FirstOrDefault() == "deny")
                await consent.DenyAsync();
            else
                await consent.GrantAsync(form["scope"].Select(scope => scope ?? string.Empty));
        });

        endpoints.MapGet(LogoutPath, async (HttpContext context, ILogoutInteraction logout) =>
        {
            var request = await logout.TryGetRequestAsync(context.RequestAborted);
            return Results.Json(new { found = request is not null, subject = request?.Subject });
        });

        endpoints.MapGet(ErrorPath, async (HttpContext context, IErrorInteraction errors) =>
        {
            var details = await errors.GetErrorAsync(context.RequestAborted);
            return Results.Json(new { kind = details?.Kind.ToString(), error = details?.Error });
        });
    }

    private static HttpClient NewClient(TestWebAppFactory factory) => factory.CreateClient(new()
    {
        BaseAddress = new Uri(Issuer),
        AllowAutoRedirect = false,
        HandleCookies = true,
    });

    private Task<HttpResponseMessage> AuthorizeAsync(string clientId, HttpClient? client = null) =>
        (client ?? _client).GetAsync(
            QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
            {
                ["client_id"] = clientId,
                ["redirect_uri"] = RegisteredRedirect,
                ["response_type"] = "code",
                ["scope"] = "openid",
                ["nonce"] = "n-0S6_WzA2Mj",
                ["code_challenge"] = Challenge,
                ["code_challenge_method"] = "S256",
            }),
            Cancellation);

    private Task<HttpResponseMessage> PostLoginAsync(string? interactionId, HttpClient? client = null) =>
        PostFormAsync(interactionId is null ? LoginPath : WithInteractionId(LoginPath, interactionId), client);

    private Task<HttpResponseMessage> GrantAsync(string interactionId) =>
        PostFormAsync(WithInteractionId(ConsentPath, interactionId), ("scope", "openid"));

    private async Task<string> ReachConsentAsync(string clientId)
    {
        var signIn = await PostLoginAsync(InteractionIdFrom(await AuthorizeAsync(clientId)));
        signIn.ShouldHaveReachedConsent();
        return InteractionIdFrom(signIn);
    }

    private async Task SignInAsync()
    {
        var signIn = await PostLoginAsync(InteractionIdFrom(await AuthorizeAsync(TrustedClient)));
        signIn.ShouldHaveIssuedCodeTo(RegisteredRedirect);
    }

    private Task<HttpResponseMessage> PostFormAsync(string url, params (string Key, string Value)[] fields) =>
        PostFormAsync(url, client: null, fields);

    private async Task<HttpResponseMessage> PostFormAsync(string url, HttpClient? client, params (string Key, string Value)[] fields)
    {
        using var content = new FormUrlEncodedContent(fields.Select(field => KeyValuePair.Create(field.Key, field.Value)));
        return await (client ?? _client).PostAsync(url, content, Cancellation);
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpClient client, string url)
    {
        var response = await client.GetAsync(url, Cancellation);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation)).RootElement.Clone();
    }

    private static string WithInteractionId(string path, string interactionId) =>
        QueryHelpers.AddQueryString(path, InteractionHandoff.InteractionIdParameter, interactionId);

    private static string InteractionIdFrom(HttpResponseMessage response)
    {
        var location = response.Headers.Location!.OriginalString;
        return QueryHelpers.ParseQuery(location[location.IndexOf('?')..])[InteractionHandoff.InteractionIdParameter]!;
    }

    /// <summary>A repository holding one registration an operator can change or remove mid-flow.</summary>
    private sealed class MutableClientRepository(IClientRegistration initial) : IClientRepository
    {
        public IClientRegistration? Current { get; set; } = initial;

        public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default) =>
            new(Current is { } current && string.Equals(current.ClientId, clientId, StringComparison.Ordinal) ? current : null);
    }

    /// <summary>Captures every log entry the host writes, after the framework's redaction.</summary>
    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly List<(LogLevel Level, string Message)> _entries = [];

        public IReadOnlyList<(LogLevel Level, string Message)> Entries
        {
            get { lock (_entries) return [.. _entries]; }
        }

        public ILogger CreateLogger(string categoryName) => new Logger(this);

        public void Dispose()
        {
        }

        private void Add(LogLevel level, string message)
        {
            lock (_entries) _entries.Add((level, message));
        }

        private sealed class Logger(CapturingLoggerProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
                owner.Add(logLevel, formatter(state, exception));
        }
    }
}

file static class RestartAssertions
{
    /// <summary>
    /// The response sent the browser to the restarting client's registered initiate_login_uri,
    /// with the issuer added and nothing else.
    /// </summary>
    public static void ShouldRestartAtTheClient(this HttpResponseMessage response)
    {
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        response.Headers.Location!.OriginalString
            .Should().Be("https://app.example.com/start?from=idp&iss=https%3A%2F%2Ftest.example.com");
    }
}
