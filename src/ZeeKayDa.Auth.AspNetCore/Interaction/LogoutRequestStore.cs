using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Stores;

using static ZeeKayDa.Auth.Stores.StoreGuard;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// A sign-out waiting for the user to confirm it: the client that asked, and where to send the
/// user afterwards. Every value was validated before it was written.
/// </summary>
internal sealed record LogoutRequestContext
{
    public required string Id { get; init; }

    public required string? ClientId { get; init; }

    public required string? PostLogoutRedirectUri { get; init; }

    public required string? State { get; init; }

    /// <summary>The SSO session the sign-out was started for — the only one it may end.</summary>
    public required string SsoSessionId { get; init; }

    /// <summary>
    /// The subject of that session, stamped when the user was asked rather than read again when
    /// the page renders. The sign-out can only complete while the browser still holds that same
    /// session, so a stale value is never one anybody is signed out on.
    /// </summary>
    public required string Subject { get; init; }

    public required DateTimeOffset ExpiresAt { get; init; }
}

/// <summary>
/// A sign-out about to be put to the user: who asked, where they go afterwards, and the session
/// that would end.
/// </summary>
internal sealed record PendingSignOut(string? ClientId, PostLogoutRedirect? Redirect, string SsoSessionId, string Subject);

/// <summary>
/// Keeps a <see cref="LogoutRequestContext"/> between the end-session endpoint and the page that
/// confirms it, on the same terms as an authorization request: an encrypted entry in the
/// interaction store, addressed by the interaction identifier and the secret in that interaction's
/// binding cookie.
/// </summary>
/// <remarks>
/// The binding cookie is what makes a confirmation this browser's own. It is <c>SameSite=Lax</c>,
/// so a cross-site form post does not carry it, and a sign-out confirmed from anywhere but the
/// page the framework sent the user to finds nothing to confirm.
/// </remarks>
internal sealed class LogoutRequestStore
{
    /// <summary>How long the user has to confirm. Not sliding.</summary>
    internal static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

    // Bumped whenever the payload's shape changes. A sign-out in flight across a deploy decodes
    // as nothing and the user starts again, which is the right way for a confirmation to fail.
    private const byte Version = 3;
    private static readonly string DataProtectionPurpose = "ZeeKayDa.Auth:LogoutRequestContext";

    private readonly IInteractionBackingStore _store;
    private readonly InteractionBindingCookie _binding;
    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;
    private readonly ISanitizingLogger<LogoutRequestStore> _logger;

    public LogoutRequestStore(
        IInteractionBackingStore store,
        InteractionBindingCookie binding,
        IDataProtectionProvider dataProtectionProvider,
        TimeProvider timeProvider,
        ISanitizingLogger<LogoutRequestStore> logger)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(dataProtectionProvider);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(logger);

        _store = store;
        _binding = binding;
        _protector = dataProtectionProvider.CreateProtector(DataProtectionPurpose);
        _timeProvider = timeProvider;
        _logger = logger;
    }

    /// <summary>
    /// Stores a sign-out for the user to confirm and binds it to this browser with a new binding
    /// cookie.
    /// </summary>
    /// <exception cref="ZeeKayDaStoreException">The backing store could not complete the write.</exception>
    public async ValueTask<LogoutRequestContext> CreateAsync(
        HttpContext context,
        PendingSignOut pending,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pending);

        var request = new LogoutRequestContext
        {
            Id = StoreKeyGenerator.Generate(),
            ClientId = pending.ClientId,
            PostLogoutRedirectUri = pending.Redirect?.Uri,
            State = pending.Redirect?.State,
            SsoSessionId = pending.SsoSessionId,
            Subject = pending.Subject,
            ExpiresAt = _timeProvider.GetUtcNow() + Lifetime,
        };

        // The entry first, the cookie second: a write the store refused leaves the browser with
        // no binding to a nothing.
        var secret = InteractionBindingCookie.NewSecret();
        var protectedValue = ProtectorFor(request.Id, secret).Protect(Encode(request));

        await Guarded(
            () => _store.SetAsync(KeyFor(request.Id, secret), protectedValue, request.ExpiresAt, cancellationToken),
            "store the sign-out request").ConfigureAwait(false);
        _binding.Issue(context, request.Id, request.ExpiresAt, secret);

        return request;
    }

    /// <summary>
    /// Reads the sign-out for <paramref name="interactionId"/>. Returns <see langword="null"/> when
    /// this browser holds no binding for it, when there is no entry, when the entry has expired or
    /// cannot be read — never throws for a value it cannot make sense of.
    /// </summary>
    /// <exception cref="ZeeKayDaStoreException">The backing store could not complete the read.</exception>
    public async ValueTask<LogoutRequestContext?> ReadAsync(HttpContext context, string interactionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        if (_binding.Read(context, interactionId) is not { } secret)
            return null;

        var stored = await Guarded(
            () => _store.GetAsync(KeyFor(interactionId, secret), cancellationToken),
            "read the sign-out request").ConfigureAwait(false);

        if (stored is null)
            return null;

        LogoutRequestContext? request;
        try
        {
            request = Decode(ProtectorFor(interactionId, secret).Unprotect(stored.Value.ToArray()));
        }
        catch (CryptographicException)
        {
            return null;
        }

        // The purpose already refuses bytes sealed for another interaction or secret; the
        // identifier and the expiry inside the payload are checked as well, since neither the
        // store's TTL nor the cookie's MaxAge is enforced by anything this framework controls.
        return request is not null
            && InteractionHandoff.IdentifiersMatch(request.Id, interactionId)
            && _timeProvider.GetUtcNow() < request.ExpiresAt
            ? request
            : null;
    }

    /// <summary>
    /// Discards the sign-out: the binding cookie, and the entry when this browser can address it.
    /// Best-effort, like discarding an authorization request: a store that refuses the removal is
    /// logged rather than thrown, and the entry is left to its lifetime.
    /// </summary>
    public async ValueTask DeleteAsync(HttpContext context, string interactionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        var secret = _binding.Read(context, interactionId);
        _binding.Delete(context, interactionId);

        if (secret is null)
            return;

        try
        {
            await Guarded(
                () => _store.RemoveAsync(KeyFor(interactionId, secret), cancellationToken),
                "remove the sign-out request").ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException ex)
        {
            _logger.LogError(ex, "Removing a completed sign-out request from the store failed; the entry is left to expire.");
        }
    }

    private static byte[] Encode(LogoutRequestContext request)
    {
        using var buffer = new MemoryStream();
        using var writer = new BinaryWriter(buffer, Encoding.UTF8, leaveOpen: true);

        writer.Write(Version);
        writer.Write(request.Id);
        WriteNullableString(writer, request.ClientId);
        WriteNullableString(writer, request.PostLogoutRedirectUri);
        WriteNullableString(writer, request.State);
        writer.Write(request.SsoSessionId);
        writer.Write(request.Subject);
        writer.Write(request.ExpiresAt.ToUnixTimeSeconds());

        writer.Flush();
        return buffer.ToArray();
    }

    private static LogoutRequestContext? Decode(byte[] payload)
    {
        try
        {
            using var buffer = new MemoryStream(payload, writable: false);
            using var reader = new BinaryReader(buffer, Encoding.UTF8, leaveOpen: true);

            if (reader.ReadByte() != Version)
                return null;

            var request = new LogoutRequestContext
            {
                Id = reader.ReadString(),
                ClientId = ReadNullableString(reader),
                PostLogoutRedirectUri = ReadNullableString(reader),
                State = ReadNullableString(reader),
                SsoSessionId = reader.ReadString(),
                Subject = reader.ReadString(),
                ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(reader.ReadInt64()),
            };

            return buffer.Position == buffer.Length ? request : null;
        }
        catch (Exception ex) when (ex is EndOfStreamException or FormatException or IOException or ArgumentException)
        {
            return null;
        }
    }

    private static void WriteNullableString(BinaryWriter writer, string? value)
    {
        writer.Write(value is not null);
        if (value is not null)
            writer.Write(value);
    }

    private static string? ReadNullableString(BinaryReader reader) => reader.ReadBoolean() ? reader.ReadString() : null;

    private static StoreKey KeyFor(string interactionId, string secret) => InteractionStoreKeys.Logout(interactionId, secret);

    private IDataProtector ProtectorFor(string interactionId, string secret) => InteractionStoreKeys.ProtectorFor(_protector, interactionId, secret);
}
