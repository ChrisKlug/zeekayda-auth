using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;

/// <summary>
/// Hand-rolled <see cref="IKeyVaultSigner"/> test double. Records every call so tests can assert
/// which Key Vault versioned URI and algorithm the service asked it to sign with, and can be
/// configured to return a caller-supplied signature or throw a caller-supplied exception —
/// simulating a real <c>CryptographyClient</c> failure (e.g. throttling) without any network
/// access.
/// </summary>
internal sealed class FakeKeyVaultSigner : IKeyVaultSigner, IDisposable
{
    public List<(Uri KeyVersionUri, string KeyLabel, SigningAlgorithm Algorithm, byte[] SigningInput)> Calls { get; } = [];

    public Func<Uri, string, SigningAlgorithm, byte[], ReadOnlyMemory<byte>>? SignFunc { get; set; }

    public Exception? ThrowException { get; set; }

    /// <summary>
    /// Number of times <see cref="Dispose"/> has been called. This test double is a stand-in for
    /// the shared, DI-owned <see cref="IKeyVaultSigner"/>/pooled <c>CryptographyClient</c> seam that
    /// every <c>KeyVaultRemoteSigner</c> activation depends on — <see cref="IKeyVaultSigner"/> itself
    /// carries no <see cref="IDisposable"/> contract, so this member only exists so a test can prove
    /// nothing in the production code path ever attempts to tear this seam down across an
    /// active-key handoff.
    /// </summary>
    public int DisposeCallCount { get; private set; }

    public ValueTask<ReadOnlyMemory<byte>> SignAsync(
        Uri keyVersionUri, string keyLabel, SigningAlgorithm algorithm, byte[] signingInput, CancellationToken cancellationToken)
    {
        Calls.Add((keyVersionUri, keyLabel, algorithm, signingInput));

        if (ThrowException is not null)
            throw ThrowException;

        var result = SignFunc?.Invoke(keyVersionUri, keyLabel, algorithm, signingInput) ?? new byte[] { 1, 2, 3, 4 };
        return ValueTask.FromResult(result);
    }

    public void Dispose() => DisposeCallCount++;
}
