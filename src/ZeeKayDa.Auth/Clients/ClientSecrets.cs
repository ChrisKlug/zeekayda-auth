using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Creates client secrets with the host's default <see cref="IClientSecretHasher"/>, and verifies a
/// presented secret against a client's stored ones in a time that reveals nothing when it fails.
/// </summary>
/// <remarks>
/// <para>
/// Owned by the framework, to be consumed, never replaced: a new algorithm is an
/// <see cref="IClientSecretHasher"/>. Sealed, with an internal constructor, so a host cannot supply its own.
/// </para>
/// <para>
/// <strong>This is CPU-intensive.</strong> The default PBKDF2 hasher performs 600,000 iterations per
/// call (~600 ms on typical server hardware). <see cref="Create(string)"/> is meant for administrative
/// operations such as client registration or secret rotation, which must be rate-limited and
/// authenticated at the application layer.
/// </para>
/// <para>
/// <strong>The plaintext is sensitive.</strong> Never log, trace or serialise it, or pass it through
/// anything that may capture method arguments. A caller holding it in a <c>char[]</c> uses the span
/// overloads and zeroes the array afterwards; the string overload leaves a copy the garbage
/// collector erases when it pleases.
/// </para>
/// </remarks>
public sealed class ClientSecrets
{
    private readonly ClientSecretHasherRegistry _registry;
    private readonly SanitizingLogger<ClientSecrets> _logger;

    internal ClientSecrets(ClientSecretHasherRegistry registry, SanitizingLogger<ClientSecrets> logger)
    {
        _registry = registry;
        _logger = logger;
    }

    /// <summary>
    /// Maximum number of active secrets a client may have simultaneously (rotation window), and so
    /// the number of failed credential slots every failed verification spends.
    /// </summary>
    internal const int MaxActiveSecretsPerClient = 2;

    /// <summary>
    /// The value every padding verification presents: fixed-length and non-empty, matching a
    /// typical client secret's length.
    /// </summary>
    internal const string DummyPresented = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; // 32 chars

    private readonly ConcurrentDictionary<Type, byte> _loggedThrowingHashers = new();

    /// <summary>Hashes <paramref name="plaintext"/> with the default hasher.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="plaintext"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="plaintext"/> is empty or whitespace.</exception>
    public ClientSecret Create(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return Create(plaintext.AsSpan());
    }

    /// <summary>Hashes <paramref name="plaintext"/> with the default hasher.</summary>
    /// <exception cref="ArgumentException">
    /// <paramref name="plaintext"/> is empty or whitespace.
    /// </exception>
    public ClientSecret Create(ReadOnlySpan<char> plaintext)
    {
        if (plaintext.IsWhiteSpace())
            throw new ArgumentException("Secret must not be empty or whitespace.", nameof(plaintext));

        var hasher = _registry.Default;
        var created = hasher.Create(plaintext)
            ?? throw new InvalidOperationException(
                $"The IClientSecretHasher '{hasher.GetType().FullName}' returned null from Create.");

        return _registry.IsHasherFor(hasher, created)
            ? created
            : throw new InvalidOperationException(
                $"The IClientSecretHasher '{hasher.GetType().FullName}' created a secret whose algorithm id " +
                "is not one of its AlgorithmIds, so no registered hasher would verify it.");
    }

    /// <summary>
    /// Whether <paramref name="presented"/> matches any of <paramref name="stored"/>, each verified by
    /// the hasher that declared its algorithm id.
    /// </summary>
    /// <remarks>
    /// A failure always costs the same: two verifications by every registered hasher, whichever
    /// secrets failed and however many there were — none included. So the time a refusal takes tells
    /// neither whether the client exists nor whether it is mid-rotation. A match returns at once.
    /// An authenticator returns the outcome through <c>ClientAuthenticationResult.From</c>, which
    /// tells the token endpoint the failure is already padded. A hasher that throws counts as a
    /// mismatch.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="stored"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="stored"/> holds more than two secrets, the most a registered client may hold.
    /// </exception>
    public SecretVerification Verify(ReadOnlySpan<char> presented, IReadOnlyCollection<ClientSecret> stored)
    {
        var candidates = WithinBudget(stored);

        // An empty secret never verifies, and the built-in hasher returns without deriving for one,
        // so trying it against each stored secret would cost nothing and pad short.
        var attempted = 0;
        if (!presented.IsEmpty)
        {
            foreach (var secret in candidates)
            {
                if (VerifyInFailedCredentialSlot(presented, secret))
                    return SecretVerification.Match;
                attempted++;
            }
        }

        for (var i = attempted; i < MaxActiveSecretsPerClient; i++)
            FinishFailedCredentialSlot(alreadyVerifiedBy: null);
        return SecretVerification.Mismatch();
    }

    /// <summary>
    /// The stored secrets, refused before any is verified when there are more than the budget pads
    /// for. Counted by enumerating, never from <c>Count</c>, which a store's collection can misreport.
    /// </summary>
    private static List<ClientSecret> WithinBudget(IReadOnlyCollection<ClientSecret> stored)
    {
        ArgumentNullException.ThrowIfNull(stored);

        var candidates = stored.Take(MaxActiveSecretsPerClient + 1).ToList();
        return candidates.Count <= MaxActiveSecretsPerClient
            ? candidates
            : throw new ArgumentException(
                $"A client holds at most {MaxActiveSecretsPerClient} secrets; more would fail in more than the padded budget.",
                nameof(stored));
    }

    /// <summary>
    /// Verifies one stored secret, and on failure spends the rest of its failed credential slot.
    /// </summary>
    private bool VerifyInFailedCredentialSlot(ReadOnlySpan<char> presented, ClientSecret? stored)
    {
        var owner = _registry.HasherFor(stored);
        if (owner is null)
        {
            FinishFailedCredentialSlot(alreadyVerifiedBy: null);
            return false;
        }

        if (SafeVerify(owner, presented, stored!, out var threw))
            return true;

        // A hasher that threw may have stopped before doing its work, so its decoy is spent too.
        FinishFailedCredentialSlot(alreadyVerifiedBy: threw ? null : owner);
        return false;
    }

    /// <summary>
    /// A failed credential slot is one verification by every registered hasher, so its cost is the
    /// same whichever hasher's secret failed, or whether there was a secret at all.
    /// </summary>
    private void FinishFailedCredentialSlot(IClientSecretHasher? alreadyVerifiedBy)
    {
        foreach (var (hasher, decoy) in _registry.TimingDecoys)
        {
            if (!ReferenceEquals(hasher, alreadyVerifiedBy))
                SafeVerify(hasher, DummyPresented.AsSpan(), decoy, out _);
        }
    }

    /// <summary>
    /// The hasher's answer; <see langword="false"/>, with <paramref name="threw"/> set, when it threw.
    /// Logged once per hasher type, by exception type only: the trigger is a request, so logging
    /// every throw would be an unauthenticated log-amplification lever.
    /// </summary>
    private bool SafeVerify(
        IClientSecretHasher hasher, ReadOnlySpan<char> presented, ClientSecret stored, out bool threw)
    {
        threw = false;
        try
        {
            return hasher.Verify(presented, stored);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (_loggedThrowingHashers.TryAdd(hasher.GetType(), 0))
            {
                _logger.LogError(
                    "The IClientSecretHasher '{Hasher}' threw {ExceptionType} from Verify; the verification failed. " +
                    "Verify must return false rather than throw. Further throws from this hasher are not logged.",
                    hasher.GetType().FullName,
                    ex.GetType().FullName);
            }

            threw = true;
            return false;
        }
    }
}
