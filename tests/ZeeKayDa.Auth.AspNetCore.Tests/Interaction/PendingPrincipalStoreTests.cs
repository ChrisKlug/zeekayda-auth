using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// The store-backed parked principal: what the resume endpoint parks is what the host page reads
/// back, for the browser that holds the interaction, once, and never past its lifetime.
/// </summary>
public sealed class PendingPrincipalStoreTests
{
    private const string InteractionId = "interaction-id";
    private const string Provider = "acme";
    private static readonly DateTimeOffset Now = new(2026, 9, 8, 12, 0, 0, TimeSpan.Zero);
    private static readonly CancellationToken None = CancellationToken.None;

    [Fact]
    public async Task Parked_principal_round_trips_with_its_identities_and_provider()
    {
        var (pending, _, _) = Store();
        var bound = BoundRequest();

        await pending.ParkAsync(bound, Ticket(), ContextAt(Now), None);
        var read = await pending.ReadAsync(RequestCarrying(bound), InteractionId, None);

        read.Should().NotBeNull();
        read!.Provider.Should().Be(Provider);
        read.Principal.Identities.Select(identity => identity.AuthenticationType).Should().Equal("acme", "acme-directory");
        read.Principal.FindFirst("sub")!.Value.Should().Be("upstream-42");
        read.Principal.FindFirst("sub")!.Issuer.Should().Be("acme");
        read.Principal.Identities.First().NameClaimType.Should().Be("name");
        read.Principal.Identities.Last().FindFirst("dept")!.Value.Should().Be("sales");
    }

    [Fact]
    public async Task Reserved_claims_are_stripped_before_parking()
    {
        var (pending, _, _) = Store();
        var bound = BoundRequest();
        var principal = ProviderPrincipal();
        principal.Identities.First().AddClaim(new Claim(ReservedClaims.Prefix + "sid", "forged"));

        await pending.ParkAsync(bound, new PendingTicket(principal, Provider), ContextAt(Now), None);

        (await pending.ReadAsync(RequestCarrying(bound), InteractionId, None))!.Principal.Claims
            .Should().NotContain(claim => claim.Type.StartsWith(ReservedClaims.Prefix));
    }

    [Fact]
    public async Task Parking_from_a_request_without_the_binding_is_refused_rather_than_creating_an_unreachable_entry()
    {
        var (pending, _, backing) = Store();

        var park = async () => await pending.ParkAsync(new DefaultHttpContext(), Ticket(), ContextAt(Now), None);

        await park.Should().ThrowAsync<InvalidOperationException>();
        backing.Count.Should().Be(0);
    }

    [Fact]
    public async Task Parking_again_replaces_the_principal()
    {
        var (pending, _, backing) = Store();
        var bound = BoundRequest();
        await pending.ParkAsync(bound, Ticket(), ContextAt(Now), None);

        await pending.ParkAsync(bound, Ticket("upstream-99"), ContextAt(Now), None);

        backing.Count.Should().Be(1);
        (await pending.ReadAsync(RequestCarrying(bound), InteractionId, None))!.Principal.FindFirst("sub")!.Value.Should().Be("upstream-99");
    }

    [Fact]
    public async Task Another_browser_reads_nothing_even_knowing_the_identifier()
    {
        var (pending, _, _) = Store();
        var bound = BoundRequest();
        await pending.ParkAsync(bound, Ticket(), ContextAt(Now), None);

        (await pending.ReadAsync(new DefaultHttpContext(), InteractionId, None)).Should().BeNull();
    }

    [Fact]
    public async Task A_forged_binding_cookie_reads_nothing()
    {
        var (pending, _, _) = Store();
        var bound = BoundRequest();
        await pending.ParkAsync(bound, Ticket(), ContextAt(Now), None);

        var forged = new DefaultHttpContext();
        forged.Request.Headers.Cookie =
            $"{InteractionBindingCookie.NamePrefix}{InteractionId}={Now.ToUnixTimeSeconds()}.{StoreKeyGenerator.Generate()}";

        (await pending.ReadAsync(forged, InteractionId, None)).Should().BeNull();
    }

    [Fact]
    public async Task Another_interactions_binding_reads_nothing()
    {
        // The second tab holds a binding of its own; it addresses its own entry, not the first
        // tab's.
        var (pending, _, _) = Store();
        var bound = BoundRequest();
        await pending.ParkAsync(bound, Ticket(), ContextAt(Now), None);
        var secondTab = BoundRequest("second-interaction");

        (await pending.ReadAsync(RequestCarrying(secondTab), "second-interaction", None)).Should().BeNull();
    }

    [Fact]
    public async Task Expired_principal_reads_nothing()
    {
        var (pending, time, _) = Store();
        var bound = BoundRequest();
        await pending.ParkAsync(bound, Ticket(), ContextAt(Now), None);

        time.Advance(PendingPrincipalStore.Lifetime + TimeSpan.FromSeconds(1));

        (await pending.ReadAsync(RequestCarrying(bound), InteractionId, None)).Should().BeNull();
    }

    [Fact]
    public async Task Principal_is_not_readable_at_the_expiry_instant()
    {
        var (pending, time, _) = Store();
        var bound = BoundRequest();
        await pending.ParkAsync(bound, Ticket(), ContextAt(Now), None);

        time.Advance(PendingPrincipalStore.Lifetime);

        (await pending.ReadAsync(RequestCarrying(bound), InteractionId, None)).Should().BeNull(
            "expiry is exclusive — the instant the window closes is outside it");
    }

    [Fact]
    public async Task A_principal_parked_late_in_the_interaction_expires_with_it()
    {
        // The interaction has five minutes left; the parked principal gets those five, not its
        // own fifteen.
        var (pending, time, _) = Store();
        var bound = BoundRequest();
        await pending.ParkAsync(bound, Ticket(), ContextAt(Now) with { ExpiresAt = Now.AddMinutes(5) }, None);

        time.Advance(TimeSpan.FromMinutes(5));

        (await pending.ReadAsync(RequestCarrying(bound), InteractionId, None)).Should().BeNull();
    }

    [Fact]
    public async Task Expiry_is_read_from_the_payload_not_the_store()
    {
        // The in-memory store here never evicts on its own. The copy inside the encrypted payload
        // is the one nothing outside this framework controls, so that is the one enforced.
        var (pending, time, backing) = Store();
        var bound = BoundRequest();
        await pending.ParkAsync(bound, Ticket(), ContextAt(Now), None);

        time.Advance(PendingPrincipalStore.Lifetime + TimeSpan.FromMinutes(1));

        backing.Count.Should().Be(1, "the backing store still holds the entry");
        (await pending.ReadAsync(RequestCarrying(bound), InteractionId, None)).Should().BeNull();
    }

    [Fact]
    public async Task Entry_protected_under_another_key_reads_nothing()
    {
        var backing = new NeverEvictingStore();
        var bound = BoundRequest();
        await Store(backing).Pending.ParkAsync(bound, Ticket(), ContextAt(Now), None);

        // A second application on the same store, or the same one after a key-ring loss.
        (await Store(backing).Pending.ReadAsync(RequestCarrying(bound), InteractionId, None)).Should().BeNull();
    }

    [Fact]
    public async Task Stored_bytes_are_opaque_and_the_key_names_neither_identifier_nor_secret()
    {
        var (pending, _, backing) = Store();
        var bound = BoundRequest();
        await pending.ParkAsync(bound, Ticket(), ContextAt(Now), None);

        var (key, value) = backing.Single();

        key.ToString().Should().StartWith("zkd:interaction:p:").And.NotContain(InteractionId).And.NotContain(SecretOf(bound));
        Encoding.UTF8.GetString(value).Should().NotContain("upstream-42").And.NotContain(InteractionId);
    }

    [Fact]
    public async Task The_parked_principal_and_the_context_are_separate_entries()
    {
        // Same binding, same identifier, two entries: parking never overwrites the context, and
        // the context store never reads the principal.
        var backing = new NeverEvictingStore();
        var (pending, time, _) = Store(backing);
        var contexts = ContextStore(backing, time);
        var write = new DefaultHttpContext();
        await contexts.TryStoreAsync(write, ContextAt(Now), 16 * 1024, None);

        await pending.ParkAsync(write, Ticket(), ContextAt(Now), None);

        backing.Count.Should().Be(2);
        (await contexts.ReadAsync(RequestCarrying(write), InteractionId, None)).Should().BeEquivalentTo(ContextAt(Now));
        (await pending.ReadAsync(RequestCarrying(write), InteractionId, None)).Should().NotBeNull();
    }

    [Fact]
    public async Task Context_bytes_cannot_be_read_as_a_parked_principal()
    {
        // Both are protected on the same key ring. Only the Data Protection purpose keeps one from
        // being accepted as the other.
        var keyRing = new EphemeralDataProtectionProvider();
        var backing = new NeverEvictingStore();
        var (pending, _, _) = Store(backing, keyRing);
        var bound = BoundRequest();
        await pending.ParkAsync(bound, Ticket(), ContextAt(Now), None);
        var (key, _) = backing.Single();

        var ticket = new AuthenticationTicket(ProviderPrincipal(), new AuthenticationProperties(), ZeeKayDaCookies.Pending);
        ticket.Properties.Items[PendingTicketItems.InteractionId] = InteractionId;
        ticket.Properties.Items[PendingTicketItems.Provider] = Provider;
        ticket.Properties.ExpiresUtc = Now.AddMinutes(10);
        var foreign = keyRing.CreateProtector("ZeeKayDa.Auth:AuthorizationRequestContext").Protect(TicketSerializer.Default.Serialize(ticket));
        await backing.SetAsync(key, foreign, Now.AddMinutes(10), None);

        (await pending.ReadAsync(RequestCarrying(bound), InteractionId, None)).Should().BeNull();
    }

    [Fact]
    public async Task Corrupt_bytes_under_a_valid_seal_read_nothing_rather_than_throwing()
    {
        // Sealed under the right purpose, so they unprotect — and then end partway through the
        // ticket. Only the framework's own writes could produce this; it still reads as absent.
        var keyRing = new EphemeralDataProtectionProvider();
        var backing = new NeverEvictingStore();
        var (pending, _, _) = Store(backing, keyRing);
        var bound = BoundRequest();
        await pending.ParkAsync(bound, Ticket(), ContextAt(Now), None);
        var (key, _) = backing.Single();
        var whole = TicketSerializer.Default.Serialize(new AuthenticationTicket(ProviderPrincipal(), ZeeKayDaCookies.Pending));
        var truncated = keyRing.CreateProtector("ZeeKayDa.Auth:PendingPrincipal").CreateProtector(InteractionId, SecretOf(bound)).Protect(whole[..(whole.Length / 2)]);
        await backing.SetAsync(key, truncated, Now.AddMinutes(10), None);

        var read = async () => await pending.ReadAsync(RequestCarrying(bound), InteractionId, None);

        (await read.Should().NotThrowAsync()).Which.Should().BeNull();
    }

    [Fact]
    public async Task Valid_ciphertext_moved_under_another_interactions_key_reads_nothing()
    {
        // Data Protection authenticates the bytes, not the row they sit in. Whoever can write to the
        // store without holding the keys could move one interaction's parked principal under
        // another's key; the identifier inside the ticket is what ties the two together.
        var backing = new NeverEvictingStore();
        var (pending, _, _) = Store(backing);
        var victim = BoundRequest();
        await pending.ParkAsync(victim, Ticket(), ContextAt(Now), None);
        var attacker = BoundRequest("attackers-interaction");
        await pending.ParkAsync(attacker, Ticket("attacker"), ContextAt(Now) with { Id = "attackers-interaction" }, None);

        backing.Swap();

        (await pending.ReadAsync(RequestCarrying(victim), InteractionId, None)).Should().BeNull(
            "the substituted entry names another interaction, so it is not this one");
    }

    [Fact]
    public async Task Valid_ciphertext_relocated_under_a_chosen_secret_for_the_same_interaction_reads_nothing()
    {
        // The identifier leaks; the secret does not. A writer to the store who knows the
        // identifier could copy the victim's parked principal under the key for that identifier
        // and a secret of their own, then present that secret in a forged cookie and have the
        // host's page link the victim's provider identity to their account. The ticket names the
        // right interaction, so only the purpose the bytes were sealed under can refuse it.
        var (pending, _, backing) = Store();
        var bound = BoundRequest();
        await pending.ParkAsync(bound, Ticket(), ContextAt(Now), None);
        var (_, ciphertext) = backing.Single();
        var chosenSecret = InteractionBindingCookie.NewSecret();
        await backing.SetAsync(InteractionStoreKeys.PendingPrincipal(InteractionId, chosenSecret), ciphertext, Now.AddMinutes(15), None);
        var attacker = new DefaultHttpContext();
        attacker.Request.Headers.Cookie = $"{InteractionBindingCookie.NamePrefix}{InteractionId}={Now.ToUnixTimeSeconds()}.{chosenSecret}";

        (await pending.ReadAsync(attacker, InteractionId, None)).Should().BeNull();
    }

    [Fact]
    public async Task Consuming_returns_the_principal_and_removes_the_entry()
    {
        var (pending, _, backing) = Store();
        var bound = BoundRequest();
        await pending.ParkAsync(bound, Ticket(), ContextAt(Now), None);

        var consumed = await pending.ConsumeAsync(RequestCarrying(bound), InteractionId, None);

        consumed.Should().NotBeNull();
        backing.Count.Should().Be(0);
        (await pending.ReadAsync(RequestCarrying(bound), InteractionId, None)).Should().BeNull("a parked principal is single-use");
    }

    [Fact]
    public async Task Consuming_from_another_browser_returns_nothing_and_leaves_the_entry_alone()
    {
        var (pending, _, backing) = Store();
        var bound = BoundRequest();
        await pending.ParkAsync(bound, Ticket(), ContextAt(Now), None);

        (await pending.ConsumeAsync(new DefaultHttpContext(), InteractionId, None)).Should().BeNull();

        backing.Count.Should().Be(1);
    }

    [Fact]
    public async Task Consuming_still_returns_the_principal_when_the_store_refuses_the_removal()
    {
        // The sign-in in progress is not replaced by a failure to tidy up; the entry is left to
        // its lifetime.
        var backing = new NeverEvictingStore { RefuseRemoval = true };
        var (pending, _, _) = Store(backing);
        var bound = BoundRequest();
        await pending.ParkAsync(bound, Ticket(), ContextAt(Now), None);

        var consumed = await pending.ConsumeAsync(RequestCarrying(bound), InteractionId, None);

        consumed.Should().NotBeNull();
        backing.Count.Should().Be(1);
    }

    [Fact]
    public async Task A_cancelled_read_throws_even_when_the_browser_holds_no_binding()
    {
        // The binding check answers without the store, so it must not answer ahead of the token:
        // a caller that stopped waiting gets the cancellation, not an absence.
        var (pending, _, _) = Store();
        var cancelled = new CancellationToken(canceled: true);

        var read = async () => await pending.ReadAsync(new DefaultHttpContext(), InteractionId, cancelled);
        var consume = async () => await pending.ConsumeAsync(new DefaultHttpContext(), InteractionId, cancelled);

        await read.Should().ThrowAsync<OperationCanceledException>();
        await consume.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task A_backing_store_fault_surfaces_as_a_store_exception_not_as_absence()
    {
        var (pending, _, _) = Store(new ThrowingStore());
        var read = new DefaultHttpContext();
        read.Request.Headers.Cookie = $"{InteractionBindingCookie.NamePrefix}{InteractionId}=1.secret";

        var act = async () => await pending.ReadAsync(read, InteractionId, None);

        (await act.Should().ThrowAsync<ZeeKayDaStoreException>())
            .Which.InnerException.Should().BeOfType<InvalidOperationException>();
    }

    // ── Fixture ───────────────────────────────────────────────────────────────────────────────

    private static (PendingPrincipalStore Pending, FakeTimeProvider Time, NeverEvictingStore Backing) Store(
        IInteractionBackingStore? backing = null,
        IDataProtectionProvider? keyRing = null)
    {
        var time = new FakeTimeProvider(Now);
        var store = backing ?? new NeverEvictingStore();

        return (
            new PendingPrincipalStore(
                store,
                new InteractionBindingCookie(time),
                keyRing ?? new EphemeralDataProtectionProvider(),
                time,
                NullSanitizingLogger<PendingPrincipalStore>.Instance),
            time,
            store as NeverEvictingStore ?? new NeverEvictingStore());
    }

    private static AuthorizationRequestContextStore ContextStore(IInteractionBackingStore backing, FakeTimeProvider time) =>
        new(
            backing,
            new InteractionBindingCookie(time),
            new EphemeralDataProtectionProvider(),
            time,
            NullSanitizingLogger<AuthorizationRequestContextStore>.Instance);

    /// <summary>A request in the middle of an interaction this browser started: the binding was issued to it.</summary>
    private static DefaultHttpContext BoundRequest(string interactionId = InteractionId)
    {
        var context = new DefaultHttpContext();
        new InteractionBindingCookie(new FakeTimeProvider(Now))
            .Issue(context, interactionId, Now + AuthorizationRequestContextStore.Lifetime, InteractionBindingCookie.NewSecret());
        return context;
    }

    /// <summary>Re-presents every Set-Cookie value as a request Cookie header, the way a browser would.</summary>
    private static DefaultHttpContext RequestCarrying(HttpContext written)
    {
        var read = new DefaultHttpContext();
        read.Request.Headers.Cookie = string.Join("; ", written.Response.Headers.SetCookie.Select(header => header!.Split(';')[0]));
        return read;
    }

    private static string SecretOf(HttpContext written) =>
        written.Response.Headers.SetCookie.Single()!.Split(';')[0].Split('=')[1].Split('.')[1];

    /// <summary>What resume parks: the provider's principal, and the provider that returned it.</summary>
    private static PendingTicket Ticket(string subject = "upstream-42") => new(ProviderPrincipal(subject), Provider);

    /// <summary>What a provider returns: two identities, each with its authentication type and issuer.</summary>
    private static ClaimsPrincipal ProviderPrincipal(string subject = "upstream-42")
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", subject, ClaimValueTypes.String, "acme"), new Claim("name", "Upstream User", ClaimValueTypes.String, "acme")],
            "acme",
            "name",
            "role"));
        principal.AddIdentity(new ClaimsIdentity([new Claim("dept", "sales", ClaimValueTypes.String, "acme")], "acme-directory"));
        return principal;
    }

    private static AuthorizationRequestContext ContextAt(DateTimeOffset now) => new()
    {
        Id = InteractionId,
        ClientId = "test-client",
        RedirectUri = "https://client.example.com/callback",
        Scopes = ["openid"],
        State = null,
        Nonce = "n-0S6_WzA2Mj",
        CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        CodeChallengeMethod = CodeChallengeMethod.S256,
        Prompts = new HashSet<PromptValue>(),
        MaxAge = null,
        IssuedAt = now,
        ExpiresAt = now + AuthorizationRequestContextStore.Lifetime,
    };

    /// <summary>A backing store that keeps everything forever, so the tests can see what is in it.</summary>
    private sealed class NeverEvictingStore : IInteractionBackingStore
    {
        private readonly Dictionary<StoreKey, byte[]> _entries = [];

        public bool RefuseRemoval { get; init; }

        public int Count => _entries.Count;

        public (StoreKey Key, byte[] Value) Single()
        {
            var (key, value) = _entries.Single();
            return (key, value);
        }

        /// <summary>Exchanges the values of the two entries held: what an attacker with write access to the store could do.</summary>
        public void Swap()
        {
            var (first, second) = (_entries.Keys.First(), _entries.Keys.Last());
            (_entries[first], _entries[second]) = (_entries[second], _entries[first]);
        }

        public ValueTask SetAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken)
        {
            _entries[key] = value.ToArray();
            return ValueTask.CompletedTask;
        }

        public ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken) =>
            ValueTask.FromResult(_entries.TryGetValue(key, out var value) ? (ReadOnlyMemory<byte>?)value : null);

        public ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken)
        {
            if (RefuseRemoval)
                throw new InvalidOperationException("store refused the removal");

            _entries.Remove(key);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ThrowingStore : IInteractionBackingStore
    {
        public ValueTask SetAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("store is down");

        public ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("store is down");

        public ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("store is down");
    }
}
