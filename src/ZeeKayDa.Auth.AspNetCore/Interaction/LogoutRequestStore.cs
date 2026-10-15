using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Stores;

using static ZeeKayDa.Auth.Stores.StoreGuard;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>A sign-out waiting for the user to confirm it, every value validated before it was written.</summary>
internal sealed record LogoutRequestContext
{
    public required string Id { get; init; }

    public required string? ClientId { get; init; }

    public required string? PostLogoutRedirectUri { get; init; }

    public required string? State { get; init; }

    /// <summary>The SSO session the sign-out was started for — the only one it may end.</summary>
    public required string SsoSessionId { get; init; }

    /// <summary>The subject of that session, as of when the user was asked.</summary>
    public required string Subject { get; init; }

    public required DateTimeOffset ExpiresAt { get; init; }
}

/// <summary>A sign-out about to be put to the user.</summary>
internal sealed record PendingSignOut(string? ClientId, PostLogoutRedirect? Redirect, string SsoSessionId, string Subject);

/// <summary>
/// Keeps a <see cref="LogoutRequestContext"/> for the confirming page, on the same terms as
/// <see cref="AuthorizationRequestContextStore"/>; a cross-site post lacks the Lax binding cookie.
/// </summary>
internal sealed class LogoutRequestStore(
    IInteractionBackingStore store,
    InteractionBindingCookie binding,
    IDataProtectionProvider dataProtectionProvider,
    TimeProvider timeProvider,
    SanitizingLogger<LogoutRequestStore> logger)
{
    /// <summary>How long the user has to confirm. Not sliding.</summary>
    internal static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

    // Bump on any payload change: a sign-out in flight across the deploy then decodes as nothing.
    private const byte Version = 3;
    private static readonly string DataProtectionPurpose = "ZeeKayDa.Auth:LogoutRequestContext";

    private readonly IDataProtector _protector = dataProtectionProvider.CreateProtector(DataProtectionPurpose);

    /// <summary>Stores a sign-out for the user to confirm, under a new binding cookie.</summary>
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
            ExpiresAt = timeProvider.GetUtcNow() + Lifetime,
        };

        // Entry before cookie: a refused write must leave no binding.
        var secret = InteractionBindingCookie.NewSecret();
        var protectedValue = ProtectorFor(request.Id, secret).Protect(Encode(request));

        await Guarded(
            () => store.SetAsync(KeyFor(request.Id, secret), protectedValue, request.ExpiresAt, cancellationToken),
            "store the sign-out request").ConfigureAwait(false);
        binding.Issue(context, new(request.Id, request.ExpiresAt, secret, ClientId: null));

        return request;
    }

    /// <summary>The sign-out bound to <paramref name="interactionId"/>; anything unreadable is <see langword="null"/>.</summary>
    /// <exception cref="ZeeKayDaStoreException">The backing store could not complete the read.</exception>
    public async ValueTask<LogoutRequestContext?> ReadAsync(HttpContext context, string interactionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        if (binding.Read(context, interactionId) is not { } secret)
            return null;

        var stored = await Guarded(
            () => store.GetAsync(KeyFor(interactionId, secret), cancellationToken),
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

        // Neither the sealing purpose nor the store's TTL is trusted alone.
        return request is not null
            && InteractionHandoff.IdentifiersMatch(request.Id, interactionId)
            && timeProvider.GetUtcNow() < request.ExpiresAt
            ? request
            : null;
    }

    /// <summary>Retires the binding cookie, then removes the entry best-effort.</summary>
    public async ValueTask DeleteAsync(HttpContext context, string interactionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        var secret = binding.Read(context, interactionId);
        binding.Retire(context, interactionId);

        if (secret is null)
            return;

        try
        {
            await Guarded(
                () => store.RemoveAsync(KeyFor(interactionId, secret), cancellationToken),
                "remove the sign-out request").ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException ex)
        {
            logger.LogError(ex, "Removing a completed sign-out request from the store failed; the entry is left to expire.");
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
