using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.TestKit.Signing;

/// <summary>
/// Runs a <see cref="SigningKeyRing"/> over a signing key source on a fake clock, so a source's own
/// tests can prove how the ring that reads it behaves as time passes, without friend access to the
/// framework.
/// </summary>
/// <example>
/// <code>
/// var clock = new FakeTimeProvider(start);
/// await using var harness = await SigningKeyRingHarness.StartAsync(new MySource(clock), clock);
/// await harness.AdvanceAsync(TimeSpan.FromDays(30));
/// var signingKey = harness.Ring.Current.SigningKey;
/// </code>
/// </example>
public sealed class SigningKeyRingHarness : IAsyncDisposable
{
    private readonly FakeTimeProvider _clock;
    private readonly TimeSpan _refreshInterval;

    private SigningKeyRingHarness(SigningKeyRing ring, FakeTimeProvider clock, TimeSpan refreshInterval)
    {
        Ring = ring;
        _clock = clock;
        _refreshInterval = refreshInterval;
    }

    /// <summary>
    /// Gets the ring under test, started over the source given to <see cref="StartAsync"/>.
    /// </summary>
    public SigningKeyRing Ring { get; }

    /// <summary>
    /// Builds a ring over <paramref name="source"/> and runs its startup: one read, then the signing
    /// key's signer opened and self-tested.
    /// </summary>
    /// <param name="source">
    /// The source under test. The ring takes ownership and disposes it when the harness is disposed,
    /// or here when startup fails.
    /// </param>
    /// <param name="clock">The clock the ring follows; pass the same one to the source when it reads time.</param>
    /// <param name="options">
    /// The ring's timing rules; <see langword="null"/> for the defaults. An unset
    /// <see cref="SigningKeyOptions.RetainRetiredKeysFor"/> is resolved as a server with default
    /// options would resolve it. The caller's instance is not changed.
    /// </param>
    /// <param name="cancellationToken">A token to cancel startup.</param>
    /// <returns>The harness, with <see cref="Ring"/> initialized.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="source"/> or <paramref name="clock"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// <paramref name="options"/> breaks a rule a server with otherwise default options would enforce, or
    /// the ring refused what the source listed, as it would stop a host. An exception the source itself
    /// throws, such as from its first read, propagates unchanged.
    /// </exception>
    public static async Task<SigningKeyRingHarness> StartAsync(
        ISigningKeySource source, FakeTimeProvider clock, SigningKeyOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(clock);

        // A server with default options but these signing keys: what the ring would run in, judged by
        // the same rules, including those that span groups.
        var serverOptions = new AuthorizationServerOptions { Issuer = "https://issuer.test" };
        var resolved = serverOptions.SigningKeys;
        if (options is not null)
        {
            resolved.LeadTime = options.LeadTime;
            resolved.RefreshInterval = options.RefreshInterval;
            resolved.RetainRetiredKeysFor = options.RetainRetiredKeysFor;
        }

        resolved.RetainRetiredKeysFor ??= SigningKeyOptions.DefaultRetainRetiredKeysFor(serverOptions);
        var logger = new SanitizingLogger<SigningKeyRing>(NullLogger<SigningKeyRing>.Instance, Options.Create(serverOptions));
        var ring = new SigningKeyRing(source, clock, resolved, logger);
        try
        {
            if (serverOptions.Validate().ToArray() is { Length: > 0 } failures)
                throw new ZeeKayDaConfigurationException(failures);

            await ring.EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await DisposeQuietlyAsync(ring).ConfigureAwait(false);
            throw;
        }

        return new SigningKeyRingHarness(ring, clock, resolved.RefreshInterval);
    }

    /// <summary>
    /// Moves the clock forward by <paramref name="by"/> in one jump, then waits until the ring has
    /// caught up: at most one source read, however long the jump, then every handover due by the new
    /// time.
    /// </summary>
    /// <param name="by">How far to move the clock.</param>
    /// <param name="cancellationToken">
    /// A token to stop waiting, such as for a source whose read never completes. The ring carries on.
    /// </param>
    /// <returns>A task that completes once the ring has caught up with the clock.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="by"/> is negative.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled before the ring caught up.</exception>
    public async Task AdvanceAsync(TimeSpan by, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(by, TimeSpan.Zero);

        _clock.Advance(by);
        await Ring.LastTransition.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Moves the clock forward by one <see cref="SigningKeyOptions.RefreshInterval"/>, so the ring
    /// reads its source exactly once, and waits until it has caught up.
    /// </summary>
    /// <param name="cancellationToken">
    /// A token to stop waiting, such as for a source whose read never completes. The ring carries on.
    /// </param>
    /// <returns>A task that completes once the ring has read and caught up with the clock.</returns>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled before the ring caught up.</exception>
    public Task ReadAsync(CancellationToken cancellationToken = default) => AdvanceAsync(_refreshInterval, cancellationToken);

    /// <summary>
    /// Disposes the ring after a failed startup, swallowing anything but an <see cref="OutOfMemoryException"/>
    /// the source's own <c>Dispose</c> throws, so the startup failure is the one the test sees.
    /// </summary>
    private static async ValueTask DisposeQuietlyAsync(SigningKeyRing ring)
    {
        try
        {
            await ((IAsyncDisposable)ring).DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Intentionally swallowed: we are already unwinding a more important failure.
        }
    }

    /// <summary>
    /// Disposes the ring, which disposes its signers and then the source.
    /// </summary>
    /// <returns>A task that completes once the source has been disposed.</returns>
    public ValueTask DisposeAsync() => ((IAsyncDisposable)Ring).DisposeAsync();
}
