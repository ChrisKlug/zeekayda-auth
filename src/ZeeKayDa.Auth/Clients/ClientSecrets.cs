using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Creates and verifies client secrets through the hashers in the <see cref="ClientSecretHasherRegistry"/>,
/// holding each to the rules every hasher is held to, and pads every failed verification to one
/// fixed cost.
/// </summary>
internal sealed class ClientSecrets(ClientSecretHasherRegistry registry, SanitizingLogger<ClientSecrets> logger)
    : IClientSecrets
{
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

    /// <inheritdoc/>
    public ClientSecret Create(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return Create(plaintext.AsSpan());
    }

    /// <inheritdoc/>
    public ClientSecret Create(ReadOnlySpan<char> plaintext)
    {
        if (plaintext.IsWhiteSpace())
            throw new ArgumentException("Secret must not be empty or whitespace.", nameof(plaintext));

        var hasher = registry.Default;
        var created = hasher.Create(plaintext)
            ?? throw new InvalidOperationException(
                $"The IClientSecretHasher '{hasher.GetType().FullName}' returned null from Create.");

        return registry.IsHasherFor(hasher, created)
            ? created
            : throw new InvalidOperationException(
                $"The IClientSecretHasher '{hasher.GetType().FullName}' created a secret whose algorithm id " +
                "is not one of its AlgorithmIds, so no registered hasher would verify it.");
    }

    /// <inheritdoc/>
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
        var owner = registry.HasherFor(stored);
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
        foreach (var (hasher, decoy) in registry.TimingDecoys)
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
                logger.LogError(
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
