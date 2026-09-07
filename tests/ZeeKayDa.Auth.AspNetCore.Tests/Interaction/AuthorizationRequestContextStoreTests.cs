using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// The store-backed interaction context: what the authorize flow reads back is what it wrote, for
/// the browser that wrote it, and nothing else.
/// </summary>
public sealed class AuthorizationRequestContextStoreTests
{
    private const string InteractionId = "interaction-id";
    private static readonly DateTimeOffset Now = new(2026, 9, 6, 12, 0, 0, TimeSpan.Zero);
    private static readonly CancellationToken None = CancellationToken.None;

    [Fact]
    public async Task Written_context_round_trips()
    {
        var (contexts, _, _) = Store();
        var write = new DefaultHttpContext();
        var context = ContextAt(Now);

        await contexts.TryStoreAsync(write, context, None);

        (await contexts.ReadAsync(RequestCarrying(write), InteractionId, None)).Should().BeEquivalentTo(context);
    }

    [Fact]
    public async Task A_context_far_larger_than_any_header_could_carry_round_trips()
    {
        // The header ceiling went with the cookie; the store's own cap is 16 KB by default.
        var (contexts, _, _) = Store();
        var write = new DefaultHttpContext();
        var context = ContextAt(Now) with { State = new string('s', 10_000) };

        (await contexts.TryStoreAsync(write, context, None)).Should().BeTrue();

        (await contexts.ReadAsync(RequestCarrying(write), InteractionId, None)).Should().BeEquivalentTo(context);
    }

    [Fact]
    public async Task A_context_over_the_cap_is_refused_and_nothing_is_written()
    {
        // An authorize request needs no authentication, so what one may make the store hold is
        // bounded; nothing is stored and no binding cookie is issued for a refused one.
        var backing = new NeverEvictingStore();
        var (contexts, _, _) = Store(backing);
        var write = new DefaultHttpContext();
        var context = ContextAt(Now) with { State = new string('s', 17_000) };

        (await contexts.TryStoreAsync(write, context, None)).Should().BeFalse();

        backing.Count.Should().Be(0);
        write.Response.Headers.SetCookie.Should().BeEmpty();
    }

    [Fact]
    public async Task The_cap_is_the_hosts_to_set()
    {
        var options = new AuthorizationServerOptions();
        options.AuthorizationEndpoint.MaxRequestContextBytes = 100_000;
        var (contexts, _, _) = Store(options: options);
        var write = new DefaultHttpContext();
        var context = ContextAt(Now) with { State = new string('s', 50_000) };

        (await contexts.TryStoreAsync(write, context, None)).Should().BeTrue();
    }

    [Fact]
    public async Task An_update_from_a_request_without_the_binding_is_refused_rather_than_creating_a_second_copy()
    {
        // Every caller reads the context first, so the binding is present; a rewrite without one
        // would otherwise silently become an unbound entry under a new key.
        var backing = new NeverEvictingStore();
        var (contexts, _, _) = Store(backing);
        await contexts.TryStoreAsync(new DefaultHttpContext(), ContextAt(Now), None);

        var act = async () => await contexts.UpdateAsync(new DefaultHttpContext(), ContextAt(Now), None);

        await act.Should().ThrowAsync<InvalidOperationException>();
        backing.Count.Should().Be(1);
    }

    [Fact]
    public async Task First_write_issues_the_binding_cookie()
    {
        var (contexts, _, _) = Store();
        var write = new DefaultHttpContext();

        await contexts.TryStoreAsync(write, ContextAt(Now), None);

        write.Response.Headers.SetCookie.ToString()
            .Should().StartWith(InteractionBindingCookie.NamePrefix + InteractionId + "=");
    }

    [Fact]
    public async Task A_rewrite_from_a_bound_browser_replaces_the_entry_without_a_new_cookie()
    {
        // The sign-in adds the session to the context. It must land in the same entry, under the
        // same binding, or the next page would read the pre-authentication copy.
        var (contexts, _, _) = Store();
        var first = new DefaultHttpContext();
        await contexts.TryStoreAsync(first, ContextAt(Now), None);

        var rewrite = RequestCarrying(first);
        var authenticated = ContextAt(Now) with { SsoSessionId = "session-1", Subject = "user-1", AuthTime = Now };
        await contexts.UpdateAsync(rewrite, authenticated, None);

        rewrite.Response.Headers.SetCookie.Should().BeEmpty("the existing binding is reused, not reissued");
        (await contexts.ReadAsync(RequestCarrying(first), InteractionId, None)).Should().BeEquivalentTo(authenticated);
    }

    [Fact]
    public async Task Another_browser_reads_nothing_even_knowing_the_identifier()
    {
        // The identifier is in the URL and URLs leak. Without the binding cookie there is nothing
        // to act on.
        var (contexts, _, _) = Store();
        var write = new DefaultHttpContext();
        await contexts.TryStoreAsync(write, ContextAt(Now), None);

        (await contexts.ReadAsync(new DefaultHttpContext(), InteractionId, None)).Should().BeNull();
    }

    [Fact]
    public async Task A_forged_binding_cookie_reads_nothing()
    {
        // Knowing the identifier and the cookie's shape is not enough: the secret has to match
        // the one the entry was keyed under.
        var (contexts, _, _) = Store();
        var write = new DefaultHttpContext();
        await contexts.TryStoreAsync(write, ContextAt(Now), None);

        var forged = new DefaultHttpContext();
        forged.Request.Headers.Cookie =
            $"{InteractionBindingCookie.NamePrefix}{InteractionId}={Now.ToUnixTimeSeconds()}.{StoreKeyGenerator.Generate()}";

        (await contexts.ReadAsync(forged, InteractionId, None)).Should().BeNull();
    }

    [Fact]
    public async Task Expired_context_reads_nothing()
    {
        var (contexts, time, _) = Store();
        var write = new DefaultHttpContext();
        await contexts.TryStoreAsync(write, ContextAt(Now), None);

        time.Advance(AuthorizationRequestContextStore.Lifetime + TimeSpan.FromSeconds(1));

        (await contexts.ReadAsync(RequestCarrying(write), InteractionId, None)).Should().BeNull();
    }

    [Fact]
    public async Task Context_is_not_readable_at_the_expiry_instant()
    {
        var (contexts, time, _) = Store();
        var write = new DefaultHttpContext();
        await contexts.TryStoreAsync(write, ContextAt(Now), None);

        time.Advance(AuthorizationRequestContextStore.Lifetime);

        (await contexts.ReadAsync(RequestCarrying(write), InteractionId, None)).Should().BeNull(
            "expiry is exclusive — the instant the window closes is outside it");
    }

    [Fact]
    public async Task Expiry_is_read_from_the_payload_not_the_store()
    {
        // The in-memory store here never evicts on its own. The copy inside the encrypted payload
        // is the one nothing outside this framework controls, so that is the one enforced.
        var (contexts, time, backing) = Store(new NeverEvictingStore());
        var write = new DefaultHttpContext();
        await contexts.TryStoreAsync(write, ContextAt(Now) with { ExpiresAt = Now.AddMinutes(1) }, None);

        time.Advance(TimeSpan.FromMinutes(2));

        backing.Count.Should().Be(1, "the backing store still holds the entry");
        (await contexts.ReadAsync(RequestCarrying(write), InteractionId, None)).Should().BeNull();
    }

    [Fact]
    public async Task Entry_protected_under_another_key_reads_nothing()
    {
        var backing = new NeverEvictingStore();
        var write = new DefaultHttpContext();
        await Store(backing).Contexts.TryStoreAsync(write, ContextAt(Now), None);

        // A second application on the same store, or the same one after a key-ring loss.
        (await Store(backing).Contexts.ReadAsync(RequestCarrying(write), InteractionId, None)).Should().BeNull();
    }

    [Fact]
    public async Task Stored_bytes_are_opaque_and_the_key_names_neither_identifier_nor_secret()
    {
        // A copy of the store must not be usable to act on an interaction, nor readable.
        var backing = new NeverEvictingStore();
        var (contexts, _, _) = Store(backing);
        var write = new DefaultHttpContext();
        await contexts.TryStoreAsync(write, ContextAt(Now) with { State = "client-state-value" }, None);
        var secret = write.Response.Headers.SetCookie.ToString().Split(';')[0].Split('.')[^1];

        var (key, value) = backing.Single();

        key.ToString().Should().NotContain(InteractionId).And.NotContain(secret);
        Encoding.UTF8.GetString(value).Should().NotContain("client-state-value").And.NotContain("client.example.com");
    }

    [Fact]
    public async Task Deleting_removes_the_entry_and_the_binding_cookie()
    {
        var backing = new NeverEvictingStore();
        var (contexts, _, _) = Store(backing);
        var write = new DefaultHttpContext();
        await contexts.TryStoreAsync(write, ContextAt(Now), None);

        var delete = RequestCarrying(write);
        await contexts.DeleteAsync(delete, InteractionId, None);

        backing.Count.Should().Be(0);
        delete.Response.Headers.SetCookie.ToString()
            .Should().StartWith(InteractionBindingCookie.NamePrefix + InteractionId + "=")
            .And.Contain("expires=Thu, 01 Jan 1970");
    }

    [Fact]
    public async Task Deleting_removes_the_binding_cookie_and_does_not_throw_when_the_store_refuses_the_removal()
    {
        // Every caller is ending a request — a code already stored, an error decided, a denial —
        // and none of those outcomes should be replaced by a failure to tidy up. The cookie is the
        // only thing that lets the browser address the entry, so once it is gone the entry is
        // unreachable whatever the store did.
        var (contexts, _, _) = Store(new ThrowingStore());
        var delete = new DefaultHttpContext();
        delete.Request.Headers.Cookie = $"{InteractionBindingCookie.NamePrefix}{InteractionId}=1.secret";

        var act = async () => await contexts.DeleteAsync(delete, InteractionId, None);

        await act.Should().NotThrowAsync();
        delete.Response.Headers.SetCookie.ToString()
            .Should().StartWith(InteractionBindingCookie.NamePrefix + InteractionId + "=")
            .And.Contain("expires=Thu, 01 Jan 1970");
    }

    [Fact]
    public async Task Valid_ciphertext_moved_under_another_interactions_key_reads_nothing()
    {
        // Data Protection authenticates the bytes, not the row they sit in. Whoever can write to the
        // store without holding the keys could move one interaction's protected context under
        // another's key; the identifier inside the payload is what ties the two together.
        var backing = new NeverEvictingStore();
        var (contexts, _, _) = Store(backing);
        var victim = new DefaultHttpContext();
        await contexts.TryStoreAsync(victim, ContextAt(Now), None);
        var attackerContext = ContextAt(Now) with { Id = "attackers-interaction", RedirectUri = "https://attacker.example.net/callback" };
        await contexts.TryStoreAsync(new DefaultHttpContext(), attackerContext, None);

        backing.Swap();

        (await contexts.ReadAsync(RequestCarrying(victim), InteractionId, None)).Should().BeNull(
            "the substituted entry names another interaction, so it is not this one");
    }

    [Fact]
    public async Task Deleting_from_another_browser_leaves_the_entry_alone()
    {
        // A deny or an error in a browser that never held the binding cannot end someone else's
        // request.
        var backing = new NeverEvictingStore();
        var (contexts, _, _) = Store(backing);
        await contexts.TryStoreAsync(new DefaultHttpContext(), ContextAt(Now), None);

        await contexts.DeleteAsync(new DefaultHttpContext(), InteractionId, None);

        backing.Count.Should().Be(1);
    }

    [Fact]
    public async Task A_backing_store_fault_surfaces_as_a_store_exception_not_as_absence()
    {
        // An interaction that cannot be read fails closed and loudly. Reporting it as "expired"
        // would send the user round the flow again against a broken store.
        var (contexts, _, _) = Store(new ThrowingStore());
        var read = new DefaultHttpContext();
        read.Request.Headers.Cookie = $"{InteractionBindingCookie.NamePrefix}{InteractionId}=1.secret";

        var act = async () => await contexts.ReadAsync(read, InteractionId, None);

        (await act.Should().ThrowAsync<ZeeKayDaStoreException>())
            .Which.InnerException.Should().BeOfType<InvalidOperationException>();
    }

    [Fact]
    public async Task Error_transport_bytes_cannot_be_read_as_an_interaction_context()
    {
        // Both are protected on the same key ring. Only the Data Protection purpose keeps one from
        // being accepted as the other.
        var keyRing = new EphemeralDataProtectionProvider();
        var backing = new NeverEvictingStore();
        var (contexts, _, _) = Store(backing, keyRing);
        var write = new DefaultHttpContext();
        await contexts.TryStoreAsync(write, ContextAt(Now), None);
        var (key, _) = backing.Single();

        var foreign = keyRing.CreateProtector("ZeeKayDa.Auth:AuthorizeErrorTransport")
            .Protect(AuthorizationRequestContextSerializer.Encode(ContextAt(Now)));
        await backing.SetAsync(key, foreign, Now.AddMinutes(30), None);

        (await contexts.ReadAsync(RequestCarrying(write), InteractionId, None)).Should().BeNull();
    }

    // ── Fixture ───────────────────────────────────────────────────────────────────────────────

    private static (AuthorizationRequestContextStore Contexts, FakeTimeProvider Time, NeverEvictingStore Backing) Store(
        IInteractionBackingStore? backing = null,
        IDataProtectionProvider? keyRing = null,
        AuthorizationServerOptions? options = null)
    {
        var time = new FakeTimeProvider(Now);
        var store = backing ?? new NeverEvictingStore();

        return (
            new AuthorizationRequestContextStore(
                store,
                new InteractionBindingCookie(time),
                keyRing ?? new EphemeralDataProtectionProvider(),
                Options.Create(options ?? new AuthorizationServerOptions()),
                time,
                NullSanitizingLogger<AuthorizationRequestContextStore>.Instance),
            time,
            store as NeverEvictingStore ?? new NeverEvictingStore());
    }

    /// <summary>Re-presents every Set-Cookie value as a request Cookie header, the way a browser would.</summary>
    private static DefaultHttpContext RequestCarrying(HttpContext written)
    {
        var read = new DefaultHttpContext();
        read.Request.Headers.Cookie = string.Join("; ", written.Response.Headers.SetCookie.Select(header => header!.Split(';')[0]));
        return read;
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
