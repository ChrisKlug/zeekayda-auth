using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;

/// <summary>
/// Hand-rolled <see cref="IKeyVaultSigner"/> test double. Records every call so tests can assert
/// which Key Vault versioned URI and algorithm the service asked it to sign with, and can be
/// configured to return a caller-supplied signature or throw a caller-supplied exception —
/// simulating a real <c>CryptographyClient</c> failure (e.g. throttling) without any network
/// access.
/// </summary>
internal sealed class FakeKeyVaultSigner : IKeyVaultSigner
{
    public List<(Uri KeyVersionUri, string Kid, SigningAlgorithm Algorithm, byte[] SigningInput)> Calls { get; } = [];

    public Func<Uri, string, SigningAlgorithm, byte[], ReadOnlyMemory<byte>>? SignFunc { get; set; }

    public Exception? ThrowException { get; set; }

    public ValueTask<ReadOnlyMemory<byte>> SignAsync(
        Uri keyVersionUri, string kid, SigningAlgorithm algorithm, byte[] signingInput, CancellationToken cancellationToken)
    {
        Calls.Add((keyVersionUri, kid, algorithm, signingInput));

        if (ThrowException is not null)
            throw ThrowException;

        var result = SignFunc?.Invoke(keyVersionUri, kid, algorithm, signingInput) ?? new byte[] { 1, 2, 3, 4 };
        return ValueTask.FromResult(result);
    }
}
