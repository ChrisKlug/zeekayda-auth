using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Tests.Interaction;
using ZeeKayDa.Auth.Stores;
using static ZeeKayDa.Auth.AspNetCore.Tests.Providers.ProviderTestHost;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Providers;

/// <summary>
/// The host's say in an external sign-in: <c>OnProviderSignIn</c> at <c>/connect/resume</c>, the
/// parked principal a redirect leaves behind, and the page that reads it back and finishes.
/// </summary>
public sealed class ProviderSignInEventTests
{
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private static TestWebAppFactory NewFactory(
        Func<ProviderSignInContext, Task>? onProviderSignIn,
        Action<Microsoft.AspNetCore.Authentication.OAuth.OAuthOptions>? configureAcme = null,
        TimeProvider? time = null) =>
        new(
            configureBuilder: builder =>
            {
                builder.WithProviders(
                    auth => auth.AddOAuth("acme", "Acme", configureAcme ?? ConfigureAcme),
                    options => options.OnProviderSignIn = onProviderSignIn);
                if (time is not null)
                    builder.Services.AddSingleton(time);
            },
            mapEndpoints: MapHostPages);

    /// <summary>Authorize, pick the provider and complete the callback: the resume URL to return through.</summary>
    private static async Task<(string InteractionId, string ResumeUrl)> ReachResumeAsync(HttpClient client)
    {
        var handoff = await client.GetAsync(AuthorizeUrl(), Cancellation);
        var interactionId = InteractionIdFrom(handoff);

        return (interactionId, await ReachResumeAgainAsync(client, interactionId));
    }

    /// <summary>Pick the provider again for an interaction already in flight, and complete the callback.</summary>
    private static async Task<string> ReachResumeAgainAsync(HttpClient client, string interactionId)
    {
        var challenge = await client.PostAsync(WithInteractionId(LoginPath, interactionId), Form(("provider", "acme")), Cancellation);
        var callbackUrl = QueryHelpers.AddQueryString("/connect/callback/acme", new Dictionary<string, string?>
        {
            ["code"] = "acme-code",
            ["state"] = RedirectQueryOf(challenge)["state"].ToString(),
        });
        var callback = await client.GetAsync(callbackUrl, Cancellation);

        return callback.Headers.Location!.OriginalString;
    }

    /// <summary>Authorize, pick the provider, complete the callback, and return through resume.</summary>
    private static async Task<(string InteractionId, HttpResponseMessage Resume)> ResumeAsync(HttpClient client)
    {
        var (interactionId, resumeUrl) = await ReachResumeAsync(client);

        return (interactionId, await client.GetAsync(resumeUrl, Cancellation));
    }

    /// <summary>The user goes round the provider again for the same interaction and returns through resume.</summary>
    private static async Task<HttpResponseMessage> ResumeAgainAsync(HttpClient client, string interactionId) =>
        await client.GetAsync(await ReachResumeAgainAsync(client, interactionId), Cancellation);

    /// <summary>The user goes round the hand-written provider for an interaction in flight and returns through resume.</summary>
    private static async Task<HttpResponseMessage> ResumeThroughHandWrittenAsync(HttpClient client, string interactionId)
    {
        var challenge = await client.PostAsync(WithInteractionId(LoginPath, interactionId), Form(("provider", "hand")), Cancellation);
        var callback = await client.GetAsync(
            QueryHelpers.AddQueryString("/connect/callback/hand", "state", RedirectQueryOf(challenge)["state"].ToString()),
            Cancellation);

        return await client.GetAsync(callback.Headers.Location!.OriginalString, Cancellation);
    }

    /// <summary>How many entries the interaction store holds: one per live context, one per parked principal.</summary>
    private static int StoreEntryCount(TestWebAppFactory factory) =>
        ((InMemoryInteractionBackingStore)factory.Services.GetRequiredService<IInteractionBackingStore>()).Count;

    /// <summary>
    /// A working in-memory store whose parked-principal operations can be made to fail mid-test:
    /// the backend going away between one step of the flow and the next. The context entries keep
    /// working, so the failure lands on exactly the read or write under test.
    /// </summary>
    private sealed class FaultableInteractionStore : IInteractionBackingStore
    {
        private readonly InMemoryInteractionBackingStore _inner = new(TimeProvider.System);

        private int _pendingReads;
        private int _pendingRemoves;

        public bool FailPendingReads { get; set; }

        public bool FailPendingWrites { get; set; }

        /// <summary>Runs before every parked-principal read: a hold, so a test can act mid-flight.</summary>
        public Func<Task>? BeforePendingRead { get; set; }

        /// <summary>How many parked-principal reads the store has answered.</summary>
        public int PendingReads => Volatile.Read(ref _pendingReads);

        /// <summary>How many parked-principal removals the store has performed.</summary>
        public int PendingRemoves => Volatile.Read(ref _pendingRemoves);

        public ValueTask SetAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken) =>
            FailPendingWrites && IsPending(key) ? throw new InvalidOperationException("store is down") : _inner.SetAsync(key, value, expiresAt, cancellationToken);

        public async ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken)
        {
            if (!IsPending(key))
                return await _inner.GetAsync(key, cancellationToken);

            if (BeforePendingRead is { } hold)
                await hold();
            Interlocked.Increment(ref _pendingReads);
            if (FailPendingReads)
                throw new InvalidOperationException("store is down");

            return await _inner.GetAsync(key, cancellationToken);
        }

        public ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken)
        {
            if (IsPending(key))
                Interlocked.Increment(ref _pendingRemoves);

            return _inner.RemoveAsync(key, cancellationToken);
        }

        private static bool IsPending(StoreKey key) => key.ToString().StartsWith("zkd:interaction:p:", StringComparison.Ordinal);
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

    private static async Task<System.Text.Json.JsonElement?> ReadJsonAsync(HttpClient client, string url)
    {
        var response = await client.GetAsync(url, Cancellation);
        if (response.StatusCode == HttpStatusCode.NotFound)
            return null;

        var body = await response.Content.ReadAsStringAsync(Cancellation);
        return System.Text.Json.JsonDocument.Parse(body).RootElement.Clone();
    }

    // ── What the handler sees ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_handler_sees_the_provider_principal_the_provider_the_client_and_the_effective_scopes()
    {
        ProviderSignInContext? seen = null;
        using var factory = NewFactory(context =>
        {
            seen = context;
            return Task.CompletedTask;
        });
        using var client = NewClient(factory);

        await ResumeAsync(client);

        seen.Should().NotBeNull();
        seen!.Principal.FindFirst("sub")!.Value.Should().Be(UpstreamSubject);
        seen.Principal.Claims.Should().NotContain(claim => claim.Type.StartsWith("zkd:"));
        seen.Provider.Id.Should().Be("acme");
        seen.Provider.DisplayName.Should().Be("Acme");
        seen.Client.ClientId.Should().Be("test-client");
        seen.EffectiveScopes.Should().Equal("openid");
    }

    [Fact]
    public async Task RequestAborted_is_signalled_when_the_browser_disconnects_during_the_handler()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var proceed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var observedCancellation = false;
        var isTheRequestsToken = false;
        IHttpContextAccessor accessor = null!;
        using var factory = NewFactory(async context =>
        {
            // The handler runs on the request's own async flow, so the accessor sees the resume
            // request; a token from anywhere else would not compare equal.
            isTheRequestsToken = context.RequestAborted == accessor.HttpContext!.RequestAborted;
            entered.SetResult();
            await proceed.Task;
            observedCancellation = context.RequestAborted.IsCancellationRequested;
        });
        using var client = NewClient(factory);
        accessor = factory.Services.GetRequiredService<IHttpContextAccessor>();
        var (_, resumeUrl) = await ReachResumeAsync(client);

        // The test server links the request's abort token to the client's: cancelling the
        // client's request mid-handler is the browser going away.
        using var browser = new CancellationTokenSource();
        var resume = client.GetAsync(resumeUrl, browser.Token);
        await entered.Task.WaitAsync(Cancellation);
        await browser.CancelAsync();
        proceed.SetResult();
        try
        {
            await resume;
        }
        catch (Exception)
        {
            // How the aborted request surfaces on the client side is not what is under test.
        }

        isTheRequestsToken.Should().BeTrue("the handler's token is the request's own");
        observedCancellation.Should().BeTrue("the disconnect reached the handler");
    }

    [Fact]
    public async Task A_handler_that_changes_the_principal_it_was_handed_does_not_change_what_is_promoted()
    {
        using var factory = NewFactory(context =>
        {
            // What a host keeping a reference and mutating it later could do, done synchronously
            // so the test is deterministic: the framework must promote its own copy regardless.
            context.Principal.Identities.First().AddClaim(new System.Security.Claims.Claim("role", "admin"));
            context.Principal.Identities.First().RemoveClaim(context.Principal.FindFirst("sub"));
            context.Principal.Identities.First().AddClaim(new System.Security.Claims.Claim("sub", "chosen", "s", "acme"));
            return Task.CompletedTask;
        });
        using var client = NewClient(factory);

        var (_, resume) = await ResumeAsync(client);

        resume.ShouldHaveReachedConsent();
        var session = (await ReadJsonAsync(client, "/test/session"))!.Value;
        session.GetProperty("sub").GetString().Should().Be(ExternalSubject.Derive("acme", "acme", UpstreamSubject));
    }

    [Fact]
    public async Task A_handler_that_calls_neither_terminal_method_lets_the_framework_promote()
    {
        using var factory = NewFactory(_ => Task.CompletedTask);
        using var client = NewClient(factory);

        var (_, resume) = await ResumeAsync(client);

        resume.ShouldHaveReachedConsent();
        (await ReadJsonAsync(client, "/test/session")).Should().NotBeNull();
    }

    // ── RedirectToAsync and the parked principal ──────────────────────────────────────────────

    [Fact]
    public async Task RedirectToAsync_parks_the_principal_and_sends_the_user_to_the_host_page_with_the_interaction_id()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);

        var (interactionId, resume) = await ResumeAsync(client);

        resume.StatusCode.Should().Be(HttpStatusCode.Redirect);
        resume.Headers.Location!.OriginalString.Should().Be($"{CollectMorePath}?zkd_i={interactionId}");
        resume.Headers.TryGetValues("Set-Cookie", out var cookies);
        (cookies ?? []).Should().NotContain(cookie => cookie.StartsWith("zkd.pending="), "the principal lives in the interaction store, not in a cookie");
        StoreEntryCount(factory).Should().Be(2, "the context and the parked principal");
        (await ReadJsonAsync(client, "/test/session")).Should().BeNull("nothing is promoted until the page signs in");
    }

    [Fact]
    public async Task The_host_page_reads_the_parked_principal_back_without_the_framework_claims()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var (_, resume) = await ResumeAsync(client);

        var pending = (await ReadJsonAsync(client, resume.Headers.Location!.OriginalString))!.Value;

        pending.GetProperty("sub").GetString().Should().Be(UpstreamSubject);
        pending.GetProperty("provider").GetString().Should().Be("acme");
        pending.GetProperty("reservedClaims").GetInt32().Should().Be(0);
    }

    [Fact]
    public async Task The_parked_principal_keeps_the_providers_identities()
    {
        // Every identity the provider returned, with its authentication type, comes back as it
        // was: the binding lives in the ticket, not in a flattened identity.
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath), ConfigureAcmeWithSecondaryIdentity);
        using var client = NewClient(factory);
        var (_, resume) = await ResumeAsync(client);

        var pending = (await ReadJsonAsync(client, resume.Headers.Location!.OriginalString))!.Value;

        pending.GetProperty("identities").EnumerateArray().Select(element => element.GetString())
            .Should().Equal("acme", "acme-directory");
        pending.GetProperty("dept").GetString().Should().Be("sales", "the secondary identity keeps its claims, not only its type");
        pending.GetProperty("reservedClaims").GetInt32().Should().Be(0);
    }

    // ── Finishing on the host page ────────────────────────────────────────────────────────────

    [Fact]
    public async Task SignInAsync_with_collected_claims_promotes_the_derived_subject_with_the_providers_claims_and_the_collected_ones()
    {
        // The page never sees or passes a subject: the session holds what an external sign-in
        // with no page involved would hold, plus what the page collected.
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var (_, resume) = await ResumeAsync(client);
        var collectMore = resume.Headers.Location!.OriginalString;

        var signIn = await client.PostAsync(collectMore, Form(("dept", "sales")), Cancellation);

        signIn.ShouldHaveReachedConsent();
        var session = (await ReadJsonAsync(client, "/test/session"))!.Value;
        session.GetProperty("sub").GetString().Should().Be(ExternalSubject.Derive("acme", "acme", UpstreamSubject), "the upstream subject never enters the session");
        session.GetProperty("name").GetString().Should().Be("Upstream User", "the provider's claims come along");
        session.GetProperty("dept").GetString().Should().Be("sales", "the collected claim is added");
        session.GetProperty("amr").EnumerateArray().Should().BeEmpty("nothing is stated about how the user authenticated at the provider");
        (await ReadJsonAsync(client, collectMore)).Should().BeNull("the parked principal is single-use");
        StoreEntryCount(factory).Should().Be(1, "the context stays until the flow ends; the parked principal is gone");
    }

    [Fact]
    public async Task SignInAsync_with_no_collected_claims_promotes_the_parked_principal_as_it_is()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var (_, resume) = await ResumeAsync(client);

        var signIn = await client.PostAsync(resume.Headers.Location!.OriginalString, Form(), Cancellation);

        signIn.ShouldHaveReachedConsent();
        (await ReadJsonAsync(client, "/test/session"))!.Value.GetProperty("sub").GetString().Should().Be(ExternalSubject.Derive("acme", "acme", UpstreamSubject));
    }

    [Theory]
    [InlineData("sub")]
    [InlineData("SUB")]
    [InlineData(System.Security.Claims.ClaimTypes.NameIdentifier)]
    public async Task SignInAsync_with_collected_claims_refuses_a_subject_claim_before_anything_is_read(string claimType)
    {
        // The whole point of the page's own service: a page cannot put a subject of its choosing,
        // the raw upstream one included, into the session through the collected claims. The store
        // is made to fail after the park, so a refusal that reached it would surface as a store
        // fault instead of the argument error.
        var store = new FaultableInteractionStore();
        using var factory = NewFaultableFactory(store);
        using var client = NewClient(factory);
        var (_, resume) = await ResumeAsync(client);
        var collectMore = resume.Headers.Location!.OriginalString;
        store.FailPendingReads = true;

        var signIn = async () => await client.PostAsync(collectMore, Form((claimType, "chosen")), Cancellation);

        await signIn.Should().ThrowAsync<ArgumentException>();
        store.FailPendingReads = false;
        (await ReadJsonAsync(client, "/test/session")).Should().BeNull("nothing was promoted");
        (await ReadJsonAsync(client, collectMore)).Should().NotBeNull("the parked principal is still there to finish with");
    }

    [Fact]
    public async Task SignInWithReplacedPrincipalAsync_without_a_subject_is_refused_before_the_parked_principal_is_taken()
    {
        // A principal the session would refuse must not cost the page the parked principal it
        // needs to try again.
        var store = new FaultableInteractionStore();
        using var factory = NewFaultableFactory(store);
        using var client = NewClient(factory);
        var (interactionId, resume) = await ResumeAsync(client);
        store.FailPendingReads = true;

        var signIn = async () => await client.PostAsync(WithInteractionId(CollectMorePath + "/link-direct", interactionId), Form(("name", "no subject")), Cancellation);

        await signIn.Should().ThrowAsync<ZeeKayDaInteractionException>().WithMessage("*subject*");
        store.FailPendingReads = false;
        (await ReadJsonAsync(client, "/test/session")).Should().BeNull("nothing was promoted");
        (await ReadJsonAsync(client, resume.Headers.Location!.OriginalString)).Should().NotBeNull("the parked principal is still there to finish with");
    }

    [Fact]
    public async Task SignInAsync_reads_the_parked_principal_to_validate_it_then_takes_it_once()
    {
        // One read to validate, one take, then promotion of what was taken: a further consume
        // inside the completion would remove a principal parked in the meantime while promoting
        // the earlier one.
        var store = new FaultableInteractionStore();
        using var factory = NewFaultableFactory(store);
        using var client = NewClient(factory);
        var (_, resume) = await ResumeAsync(client);
        var reads = store.PendingReads;
        var removes = store.PendingRemoves;

        var signIn = await client.PostAsync(resume.Headers.Location!.OriginalString, Form(("dept", "sales")), Cancellation);

        signIn.ShouldHaveReachedConsent();
        (store.PendingReads - reads).Should().Be(2);
        (store.PendingRemoves - removes).Should().Be(1);
    }

    [Fact]
    public async Task SignInWithReplacedPrincipalAsync_promotes_the_principal_as_validated_not_as_later_changed()
    {
        // A host that keeps a reference to the principal it passed and changes it while the
        // store is awaited signs in what was validated, not the replacement.
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var proceed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var store = new FaultableInteractionStore();
        using var factory = new TestWebAppFactory(
            configureBuilder: builder =>
            {
                builder.WithProviders(
                    auth => auth.AddOAuth("acme", "Acme", ConfigureAcme),
                    options => options.OnProviderSignIn = context => context.RedirectToAsync(CollectMorePath));
                builder.AddInMemoryAuthorizationCodeStore(allowOutsideDevelopment: true);
                builder.AddInMemoryRefreshTokenStore(allowOutsideDevelopment: true);
                builder.Services.AddSingleton<IInteractionBackingStore>(store);
            },
            mapEndpoints: endpoints =>
            {
                MapHostPages(endpoints);
                endpoints.MapPost(CollectMorePath + "/link-mutating", async (IProviderSignInInteraction signIn) =>
                {
                    var identity = new System.Security.Claims.ClaimsIdentity([new System.Security.Claims.Claim("sub", "local-1")], "test");
                    var principal = new System.Security.Claims.ClaimsPrincipal(identity);

                    var signingIn = signIn.SignInWithReplacedPrincipalAsync(principal, ZeeKayDa.Auth.Authorization.AuthenticationMethods.Password);
                    await entered.Task;
                    identity.RemoveClaim(identity.FindFirst("sub"));
                    identity.AddClaim(new System.Security.Claims.Claim("sub", "hijacked"));
                    proceed.SetResult();
                    await signingIn;
                });
            });
        using var client = NewClient(factory);
        var (interactionId, _) = await ResumeAsync(client);
        store.BeforePendingRead = async () =>
        {
            entered.TrySetResult();
            await proceed.Task;
        };

        var signIn = await client.PostAsync(WithInteractionId(CollectMorePath + "/link-mutating", interactionId), Form(), Cancellation);

        signIn.ShouldHaveReachedConsent();
        (await ReadJsonAsync(client, "/test/session"))!.Value.GetProperty("sub").GetString().Should().Be("local-1");
    }

    [Fact]
    public async Task SignInWithReplacedPrincipalAsync_selects_the_subject_as_the_session_does()
    {
        // An empty first sub claim ahead of a valid one is what the session sees as no subject:
        // refused here, before the take, not by the session after it.
        var store = new FaultableInteractionStore();
        using var factory = NewFaultableFactory(store);
        using var client = NewClient(factory);
        var (interactionId, resume) = await ResumeAsync(client);
        store.FailPendingReads = true;

        var signIn = async () => await client.PostAsync(WithInteractionId(CollectMorePath + "/link-direct", interactionId), Form(("sub", ""), ("sub", "local-1")), Cancellation);

        await signIn.Should().ThrowAsync<ZeeKayDaInteractionException>().WithMessage("*subject*");
        store.FailPendingReads = false;
        (await ReadJsonAsync(client, resume.Headers.Location!.OriginalString)).Should().NotBeNull();
    }

    [Fact]
    public async Task SignInWithReplacedPrincipalAsync_refuses_the_parked_principal_passed_straight_back()
    {
        // The bug this service exists to close, written the obvious way: the replacement is the
        // provider's principal itself, upstream subject and all. Refused before the take.
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var (interactionId, resume) = await ResumeAsync(client);

        var signIn = async () => await client.PostAsync(WithInteractionId(CollectMorePath + "/link-passthrough", interactionId), Form(), Cancellation);

        await signIn.Should().ThrowAsync<ZeeKayDaInteractionException>().WithMessage("*upstream subject*");
        (await ReadJsonAsync(client, "/test/session")).Should().BeNull("nothing was promoted");
        (await ReadJsonAsync(client, resume.Headers.Location!.OriginalString)).Should().NotBeNull("the parked principal is still there to finish with");
    }

    [Theory]
    [InlineData("sub")]
    [InlineData(System.Security.Claims.ClaimTypes.NameIdentifier)]
    public async Task SignInWithReplacedPrincipalAsync_refuses_a_copy_of_the_upstream_subject(string claimType)
    {
        // A local principal built around the upstream subject value is the same bypass with an
        // extra step, whatever the claim type or issuer.
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var (interactionId, resume) = await ResumeAsync(client);

        var signIn = async () => await client.PostAsync(WithInteractionId(CollectMorePath + "/link-direct", interactionId), Form((claimType, UpstreamSubject)), Cancellation);

        await signIn.Should().ThrowAsync<ZeeKayDaInteractionException>().WithMessage("*upstream subject*");
        (await ReadJsonAsync(client, resume.Headers.Location!.OriginalString)).Should().NotBeNull();
    }

    [Fact]
    public async Task SignInWithReplacedPrincipalAsync_holds_a_principal_parked_between_the_read_and_the_take_to_the_same_rule()
    {
        // The replacement passes against the principal read from acme; while the take is in
        // flight, the user returns through the hand-written provider, whose upstream subject the
        // replacement happens to carry. What was taken is what the rule is applied to.
        var atTake = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var proceed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var store = new FaultableInteractionStore();
        using var factory = new TestWebAppFactory(
            configureBuilder: builder =>
            {
                builder.WithProviders(
                    auth =>
                    {
                        auth.AddOAuth("acme", "Acme", ConfigureAcme);
                        AddHandWritten(auth);
                    },
                    options => options.OnProviderSignIn = context => context.RedirectToAsync(CollectMorePath));
                builder.AddInMemoryAuthorizationCodeStore(allowOutsideDevelopment: true);
                builder.AddInMemoryRefreshTokenStore(allowOutsideDevelopment: true);
                builder.Services.AddSingleton<IInteractionBackingStore>(store);
            },
            mapEndpoints: MapHostPages);
        using var client = NewClient(factory);
        var (interactionId, _) = await ResumeAsync(client);
        var reads = 0;
        store.BeforePendingRead = async () =>
        {
            if (Interlocked.Increment(ref reads) != 2)
                return;

            atTake.SetResult();
            await proceed.Task;
        };

        var signIn = client.PostAsync(WithInteractionId(CollectMorePath + "/link-direct", interactionId), Form(("sub", HandWrittenSubject)), Cancellation);
        await atTake.Task.WaitAsync(Cancellation);
        store.BeforePendingRead = null;
        await ResumeThroughHandWrittenAsync(client, interactionId);
        proceed.SetResult();

        var completion = async () => await signIn;
        await completion.Should().ThrowAsync<ZeeKayDaInteractionException>().WithMessage("*upstream subject*");
        (await ReadJsonAsync(client, "/test/session")).Should().BeNull("nothing was promoted");
    }

    [Fact]
    public async Task Both_sign_ins_from_the_host_page_record_the_provider_that_parked_the_principal()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var (collected, collectedResume) = await ResumeAsync(client);
        var (replaced, _) = await ResumeAsync(client);

        (await client.PostAsync(collectedResume.Headers.Location!.OriginalString, Form(), Cancellation)).ShouldHaveReachedConsent();
        (await client.PostAsync(WithInteractionId(CollectMorePath + "/link", replaced), Form(), Cancellation)).ShouldHaveReachedConsent();

        (await ReadJsonAsync(client, WithInteractionId("/test/request-context", collected)))!.Value.GetProperty("providerScheme").GetString().Should().Be("acme");
        (await ReadJsonAsync(client, WithInteractionId("/test/request-context", replaced)))!.Value.GetProperty("providerScheme").GetString().Should().Be("acme");
    }

    [Fact]
    public async Task A_local_sign_in_at_the_login_page_discards_a_parked_principal_and_records_no_provider()
    {
        // The login page signs in the host's own principal: a principal parked for the
        // interaction is neither adopted nor left behind, and a password sign-in is not reported
        // as an external one.
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var (interactionId, resume) = await ResumeAsync(client);

        var signIn = await client.PostAsync(WithInteractionId(LoginPath, interactionId), Form(("sub", "user-1")), Cancellation);

        signIn.ShouldHaveReachedConsent();
        var recorded = (await ReadJsonAsync(client, WithInteractionId("/test/request-context", interactionId)))!.Value;
        recorded.GetProperty("providerScheme").ValueKind.Should().Be(System.Text.Json.JsonValueKind.Null);
        recorded.GetProperty("subject").GetString().Should().Be("user-1");
        (await ReadJsonAsync(client, resume.Headers.Location!.OriginalString)).Should().BeNull("the parked principal was discarded");
        StoreEntryCount(factory).Should().Be(1);
    }

    [Fact]
    public async Task SignInAsync_promotes_the_principal_parked_at_the_time_of_the_post_not_the_one_the_page_read()
    {
        // The page reads the principal from one provider; before it posts, the user goes round a
        // second provider for the same interaction, which parks over the first. The sign-in
        // promotes what it consumed, so the session and the store cannot disagree.
        using var factory = new TestWebAppFactory(
            configureBuilder: builder => builder.WithProviders(
                auth =>
                {
                    auth.AddOAuth("acme", "Acme", ConfigureAcme);
                    AddHandWritten(auth);
                },
                options => options.OnProviderSignIn = context => context.RedirectToAsync(CollectMorePath)),
            mapEndpoints: MapHostPages);
        using var client = NewClient(factory);
        var (interactionId, resume) = await ResumeAsync(client);
        var collectMore = resume.Headers.Location!.OriginalString;
        (await ReadJsonAsync(client, collectMore))!.Value.GetProperty("provider").GetString().Should().Be("acme");
        await ResumeThroughHandWrittenAsync(client, interactionId);

        var signIn = await client.PostAsync(collectMore, Form(), Cancellation);

        signIn.ShouldHaveReachedConsent();
        (await ReadJsonAsync(client, "/test/session"))!.Value.GetProperty("sub").GetString()
            .Should().Be(ExternalSubject.Derive("hand", HandWrittenIssuer, HandWrittenSubject), "the later park is what was promoted");
        StoreEntryCount(factory).Should().Be(1, "the context stays until the flow ends; the parked principal is gone");
    }

    [Fact]
    public async Task Reserved_claims_among_the_collected_ones_are_stripped()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var (_, resume) = await ResumeAsync(client);

        var signIn = await client.PostAsync(resume.Headers.Location!.OriginalString, Form(("zkd:sid", "forged"), ("ZKD:amr", "forged")), Cancellation);

        signIn.ShouldHaveReachedConsent();
        var session = (await ReadJsonAsync(client, "/test/session"))!.Value;
        session.GetProperty("sid").GetString().Should().NotBe("forged");
        session.GetProperty("amr").EnumerateArray().Should().BeEmpty();
        session.GetProperty("reservedClaims").GetInt32().Should().Be(0);
    }

    [Fact]
    public async Task SignInWithReplacedPrincipalAsync_promotes_the_replacement_and_consumes_the_parked_one()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var (interactionId, resume) = await ResumeAsync(client);
        var collectMore = resume.Headers.Location!.OriginalString;

        var signIn = await client.PostAsync(WithInteractionId(CollectMorePath + "/link", interactionId), Form(), Cancellation);

        signIn.ShouldHaveReachedConsent();
        var session = (await ReadJsonAsync(client, "/test/session"))!.Value;
        session.GetProperty("sub").GetString().Should().Be("mapped-" + UpstreamSubject, "linking holds the host's own principal, subject included");
        session.GetProperty("amr").EnumerateArray().Select(element => element.GetString()).Should().Equal("pwd");
        (await ReadJsonAsync(client, collectMore)).Should().BeNull("the parked principal is single-use");
        StoreEntryCount(factory).Should().Be(1, "the context stays until the flow ends; the parked principal is gone");
    }

    [Fact]
    public async Task SignInAsync_with_nothing_parked_is_refused_and_the_interaction_survives()
    {
        // The page finishes an external sign-in; an interaction that never went through
        // RedirectToAsync has none to finish, and the sign-in from nothing belongs to the login page.
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var handoff = await client.GetAsync(AuthorizeUrl(), Cancellation);
        var interactionId = InteractionIdFrom(handoff);

        var collected = async () => await client.PostAsync(WithInteractionId(CollectMorePath, interactionId), Form(("dept", "sales")), Cancellation);
        var linked = async () => await client.PostAsync(WithInteractionId(CollectMorePath + "/link-direct", interactionId), Form(("sub", "local-1")), Cancellation);

        await collected.Should().ThrowAsync<ZeeKayDaInteractionException>();
        await linked.Should().ThrowAsync<ZeeKayDaInteractionException>("the service itself refuses, whether or not the page read first");
        (await ReadJsonAsync(client, "/test/session")).Should().BeNull();
        var signIn = await client.PostAsync(WithInteractionId(LoginPath, interactionId), Form(("sub", "user-1")), Cancellation);
        signIn.ShouldHaveReachedConsent("the interaction is untouched");
    }

    [Fact]
    public async Task A_second_post_after_the_parked_principal_was_consumed_is_refused()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var (_, resume) = await ResumeAsync(client);
        var collectMore = resume.Headers.Location!.OriginalString;
        (await client.PostAsync(collectMore, Form(), Cancellation)).ShouldHaveReachedConsent();

        var again = async () => await client.PostAsync(collectMore, Form(), Cancellation);

        await again.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    [Fact]
    public async Task DenyAsync_on_the_host_page_answers_access_denied_naming_the_provider_stage_and_discards_both_entries()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var (interactionId, _) = await ResumeAsync(client);

        var cancel = await client.PostAsync(WithInteractionId(CollectMorePath + "/cancel", interactionId), Form(), Cancellation);

        cancel.StatusCode.Should().Be(HttpStatusCode.Redirect);
        DestinationOf(cancel).Should().Be(RegisteredRedirect);
        var query = RedirectQueryOf(cancel);
        query["error"].ToString().Should().Be("access_denied");
        query["error_description"].ToString().Should().Contain("external identity provider");
        (await ReadJsonAsync(client, "/test/session")).Should().BeNull();
        StoreEntryCount(factory).Should().Be(0, "the context and the parked principal both go with the denial");
    }

    [Fact]
    public async Task A_terminal_call_from_a_GET_is_refused_before_anything_is_read()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var (interactionId, _) = await ResumeAsync(client);

        var signIn = async () => await client.GetAsync(WithInteractionId(CollectMorePath + "/sign-in-by-get", interactionId), Cancellation);
        var cancel = async () => await client.GetAsync(WithInteractionId(CollectMorePath + "/cancel-by-get", interactionId), Cancellation);

        await signIn.Should().ThrowAsync<InvalidOperationException>();
        await cancel.Should().ThrowAsync<InvalidOperationException>();
        (await ReadJsonAsync(client, "/test/session")).Should().BeNull();
        StoreEntryCount(factory).Should().Be(2, "nothing was consumed or discarded");
    }

    [Fact]
    public async Task SignInAsync_with_collected_claims_refuses_a_parked_subject_without_an_issuer()
    {
        // The same rule promotion applies with no page involved: the derived subject needs the
        // issuer, and a parked principal without one cannot be finished through the collected
        // claims. It stays parked, and the interaction survives for the login page.
        using var factory = new TestWebAppFactory(
            configureBuilder: builder => builder.WithProviders(
                auth => AddHandWritten(auth, options => options.SubjectWithoutIssuer = true),
                options => options.OnProviderSignIn = context => context.RedirectToAsync(CollectMorePath)),
            mapEndpoints: MapHostPages);
        using var client = NewClient(factory);
        var handoff = await client.GetAsync(AuthorizeUrl(), Cancellation);
        var interactionId = InteractionIdFrom(handoff);
        var resume = await ResumeThroughHandWrittenAsync(client, interactionId);

        var signIn = async () => await client.PostAsync(resume.Headers.Location!.OriginalString, Form(), Cancellation);

        await signIn.Should().ThrowAsync<ZeeKayDaInteractionException>().WithMessage("*issuer*");
        (await ReadJsonAsync(client, "/test/session")).Should().BeNull();
        (await ReadJsonAsync(client, resume.Headers.Location!.OriginalString)).Should().NotBeNull("the refusal was decided before the parked principal was taken");
    }

    [Fact]
    public async Task A_parked_principal_bound_to_another_interaction_is_refused()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        await ResumeAsync(client);
        var secondTab = await client.GetAsync(AuthorizeUrl(), Cancellation);

        var pending = await ReadJsonAsync(client, WithInteractionId(CollectMorePath, InteractionIdFrom(secondTab)));

        pending.Should().BeNull();
    }

    [Fact]
    public async Task GetPendingPrincipalAsync_without_an_interaction_id_is_refused()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        await ResumeAsync(client);

        var read = async () => await client.GetAsync(CollectMorePath, Cancellation);

        await read.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    [Fact]
    public async Task GetPendingPrincipalAsync_honours_a_cancelled_token()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var (interactionId, _) = await ResumeAsync(client);

        var read = async () => await client.GetAsync(WithInteractionId(CollectMorePath + "/cancelled", interactionId), Cancellation);

        await read.Should().ThrowAsync<OperationCanceledException>();
    }

    /// <summary>A host on a store whose parked-principal operations can be made to fail, with its log captured.</summary>
    private static TestWebAppFactory NewFaultableFactory(FaultableInteractionStore store, CapturingLoggerProvider? logs = null) =>
        new(
            configureBuilder: builder =>
            {
                builder.WithProviders(
                    auth => auth.AddOAuth("acme", "Acme", ConfigureAcme),
                    options => options.OnProviderSignIn = context => context.RedirectToAsync(CollectMorePath));
                builder.AddInMemoryAuthorizationCodeStore(allowOutsideDevelopment: true);
                builder.AddInMemoryRefreshTokenStore(allowOutsideDevelopment: true);
                builder.Services.AddSingleton<IInteractionBackingStore>(store);
                if (logs is not null)
                    builder.Services.AddLogging(logging => logging.AddProvider(logs));
            },
            mapEndpoints: MapHostPages);

    [Fact]
    public async Task GetPendingPrincipalAsync_surfaces_a_store_fault_rather_than_reporting_nothing_parked()
    {
        // The page must not tell the user there is nothing to link because the store is down.
        var store = new FaultableInteractionStore();
        using var factory = NewFaultableFactory(store);
        using var client = NewClient(factory);
        var (_, resume) = await ResumeAsync(client);
        store.FailPendingReads = true;

        var read = async () => await client.GetAsync(resume.Headers.Location!.OriginalString, Cancellation);

        await read.Should().ThrowAsync<ZeeKayDaStoreException>();
    }

    [Fact]
    public async Task A_store_that_refuses_the_park_renders_locally_leaves_the_interaction_alive_and_logs_the_outage()
    {
        // The write inside RedirectToAsync fails: the user sees the local error and can still
        // sign in another way, and the operator sees a store outage, not a host-handler failure.
        var store = new FaultableInteractionStore { FailPendingWrites = true };
        var logs = new CapturingLoggerProvider();
        using var factory = NewFaultableFactory(store, logs);
        using var client = NewClient(factory);

        var (interactionId, resume) = await ResumeAsync(client);

        resume.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await resume.Content.ReadAsStringAsync(Cancellation)).Should().Contain("server_error");
        var signIn = await client.PostAsync(WithInteractionId(LoginPath, interactionId), Form(("sub", "user-1")), Cancellation);
        signIn.ShouldHaveReachedConsent("the interaction survived the failed park");
        logs.Entries.Should().Contain(entry =>
            entry.Level == LogLevel.Error && entry.Message.Contains("the interaction store could not be written"));
    }

    [Fact]
    public async Task DenyAsync_still_answers_access_denied_when_the_parked_principal_cannot_be_read()
    {
        // The denial is decided and the interaction already claimed by the time the parked
        // principal is discarded; a store fault there must not leave the client waiting and the
        // user's retry refused as already completed.
        var store = new FaultableInteractionStore();
        using var factory = NewFaultableFactory(store);
        using var client = NewClient(factory);
        var (interactionId, _) = await ResumeAsync(client);
        store.FailPendingReads = true;

        var cancel = await client.PostAsync(WithInteractionId("/account/login/cancel", interactionId), Form(), Cancellation);

        cancel.StatusCode.Should().Be(HttpStatusCode.Redirect);
        DestinationOf(cancel).Should().Be(RegisteredRedirect);
        RedirectQueryOf(cancel)["error"].ToString().Should().Be("access_denied");
    }

    [Fact]
    public async Task Cancelling_at_the_host_page_discards_the_parked_principal()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var (interactionId, resume) = await ResumeAsync(client);

        var cancel = await client.PostAsync(WithInteractionId("/account/login/cancel", interactionId), Form(), Cancellation);

        cancel.StatusCode.Should().Be(HttpStatusCode.Redirect);
        StoreEntryCount(factory).Should().Be(0, "the context and the parked principal both go with the denial");
    }

    [Fact]
    public async Task RedirectToAsync_refuses_a_path_outside_the_host()
    {
        // The context throws before touching the response; the endpoint then renders the host
        // handler's failure locally, as it does any other. Nothing is parked and nothing redirects.
        using var factory = NewFactory(context => context.RedirectToAsync("//attacker.example.net/collect"));
        using var client = NewClient(factory);

        var (_, resume) = await ResumeAsync(client);

        resume.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        resume.Headers.Location.Should().BeNull();
        StoreEntryCount(factory).Should().Be(1, "only the context: nothing was parked");
    }

    [Fact]
    public async Task Calling_a_second_terminal_method_fails()
    {
        using var factory = NewFactory(async context =>
        {
            await context.RedirectToAsync(CollectMorePath);
            await context.DenyAsync();
        });
        using var client = NewClient(factory);

        var resume = async () => await ResumeAsync(client);

        await resume.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task A_handler_that_throws_renders_locally_and_leaves_the_interaction_alive()
    {
        using var factory = NewFactory(_ => throw new InvalidOperationException("provisioning store down: secret-dsn"));
        using var client = NewClient(factory);

        var (interactionId, resume) = await ResumeAsync(client);

        resume.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await resume.Content.ReadAsStringAsync(Cancellation)).Should().Contain("server_error").And.NotContain("secret-dsn");
        var signIn = await client.PostAsync(WithInteractionId(LoginPath, interactionId), Form(("sub", "user-1")), Cancellation);
        signIn.ShouldHaveReachedConsent("the interaction survived the failed handler");
    }

    [Fact]
    public async Task Automatic_promotion_consumes_a_parked_principal_bound_to_the_interaction()
    {
        // The first return parks the principal; the user goes round again for the same
        // interaction and the handler lets the framework promote this time.
        var calls = 0;
        using var factory = NewFactory(context => ++calls == 1 ? context.RedirectToAsync(CollectMorePath) : Task.CompletedTask);
        using var client = NewClient(factory);
        var (interactionId, _) = await ResumeAsync(client);

        var resume = await ResumeAgainAsync(client, interactionId);

        resume.ShouldHaveReachedConsent();
        (await ReadJsonAsync(client, WithInteractionId(CollectMorePath, interactionId))).Should().BeNull();
        StoreEntryCount(factory).Should().Be(1, "the context stays until the flow ends; the parked principal is gone");
    }

    [Fact]
    public async Task DenyAsync_consumes_a_parked_principal_bound_to_the_interaction()
    {
        var calls = 0;
        using var factory = NewFactory(context => ++calls == 1 ? context.RedirectToAsync(CollectMorePath) : context.DenyAsync());
        using var client = NewClient(factory);
        var (interactionId, _) = await ResumeAsync(client);

        var resume = await ResumeAgainAsync(client, interactionId);

        resume.StatusCode.Should().Be(HttpStatusCode.Redirect);
        StoreEntryCount(factory).Should().Be(0, "the context and the parked principal both go with the denial");
    }

    // ── Concurrent tabs ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Two_tabs_parked_at_the_host_page_each_read_back_their_own_principal_and_each_complete()
    {
        // Concurrent tabs: each interaction parks its own principal, so the second tab's park
        // replaces nothing, and the first tab's sign-in consumes only its own.
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var (firstTab, firstResume) = await ResumeAsync(client);
        var (secondTab, secondResume) = await ResumeAsync(client);

        (await ReadJsonAsync(client, firstResume.Headers.Location!.OriginalString)).Should().NotBeNull("the first tab reads its own parked principal");
        (await ReadJsonAsync(client, secondResume.Headers.Location!.OriginalString)).Should().NotBeNull("the second tab reads its own parked principal");
        var first = await client.PostAsync(WithInteractionId(CollectMorePath, firstTab), Form(), Cancellation);
        first.ShouldHaveReachedConsent();
        (await ReadJsonAsync(client, secondResume.Headers.Location!.OriginalString)).Should().NotBeNull("the first tab's sign-in consumed only its own principal");
        var second = await client.PostAsync(WithInteractionId(CollectMorePath, secondTab), Form(), Cancellation);
        second.ShouldHaveReachedConsent();
        (await ReadJsonAsync(client, "/test/session"))!.Value.GetProperty("sub").GetString().Should().Be(ExternalSubject.Derive("acme", "acme", UpstreamSubject));
    }

    [Fact]
    public async Task Automatic_promotion_in_another_tab_leaves_a_parked_principal_alone()
    {
        var calls = 0;
        using var factory = NewFactory(context => ++calls == 1 ? context.RedirectToAsync(CollectMorePath) : Task.CompletedTask);
        using var client = NewClient(factory);
        var (_, firstResume) = await ResumeAsync(client);

        var (_, secondResume) = await ResumeAsync(client);

        secondResume.ShouldHaveReachedConsent();
        (await ReadJsonAsync(client, firstResume.Headers.Location!.OriginalString)).Should().NotBeNull("the second tab completed its own interaction, not the first tab's");
    }

    [Fact]
    public async Task DenyAsync_in_another_tab_leaves_a_parked_principal_alone()
    {
        var calls = 0;
        using var factory = NewFactory(context => ++calls == 1 ? context.RedirectToAsync(CollectMorePath) : context.DenyAsync());
        using var client = NewClient(factory);
        var (_, firstResume) = await ResumeAsync(client);

        var (_, secondResume) = await ResumeAsync(client);

        secondResume.StatusCode.Should().Be(HttpStatusCode.Redirect);
        (await ReadJsonAsync(client, firstResume.Headers.Location!.OriginalString)).Should().NotBeNull("the second tab denied its own interaction, not the first tab's");
    }

    // ── Lifetime ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_parked_principal_expires_after_fifteen_minutes()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath), time: time);
        using var client = NewClient(factory);
        var (_, resume) = await ResumeAsync(client);

        time.Advance(PendingPrincipalStore.Lifetime + TimeSpan.FromSeconds(1));

        (await ReadJsonAsync(client, resume.Headers.Location!.OriginalString)).Should().BeNull("the interaction is still alive, but the parked principal is not");
    }

    [Fact]
    public async Task A_parked_principal_never_outlives_its_interaction()
    {
        // Parked twenty minutes into a thirty-minute interaction, the principal gets the ten
        // minutes the interaction has left, not fifteen of its own.
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath), time: time);
        using var client = NewClient(factory);
        var handoff = await client.GetAsync(AuthorizeUrl(), Cancellation);
        var interactionId = InteractionIdFrom(handoff);
        time.Advance(TimeSpan.FromMinutes(20));
        var resume = await ResumeAgainAsync(client, interactionId);

        time.Advance(TimeSpan.FromMinutes(11));

        (await ReadJsonAsync(client, resume.Headers.Location!.OriginalString)).Should().BeNull();
    }

    // ── DenyAsync ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task DenyAsync_answers_the_client_with_access_denied_naming_the_provider_stage()
    {
        using var factory = NewFactory(context => context.DenyAsync());
        using var client = NewClient(factory);

        var (_, resume) = await ResumeAsync(client);

        resume.StatusCode.Should().Be(HttpStatusCode.Redirect);
        DestinationOf(resume).Should().Be(RegisteredRedirect);
        var query = RedirectQueryOf(resume);
        query["error"].ToString().Should().Be("access_denied");
        query["error_description"].ToString().Should().Contain("external identity provider");
        query["iss"].ToString().Should().Be("https://test.example.com");
        (await ReadJsonAsync(client, "/test/session")).Should().BeNull();
    }

    [Fact]
    public async Task DenyAsync_discards_the_interaction()
    {
        using var factory = NewFactory(context => context.DenyAsync());
        using var client = NewClient(factory);
        var (interactionId, _) = await ResumeAsync(client);

        var signIn = async () => await client.PostAsync(WithInteractionId(LoginPath, interactionId), Form(("sub", "user-1")), Cancellation);

        await signIn.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }
}
