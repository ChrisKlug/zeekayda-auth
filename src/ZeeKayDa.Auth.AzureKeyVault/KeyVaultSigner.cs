using System.Collections.Concurrent;
using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// <see cref="IKeyVaultSigner"/> implementation backed by real
/// <see cref="Azure.Security.KeyVault.Keys.Cryptography.CryptographyClient"/> instances.
/// </summary>
/// <remarks>
/// One <see cref="CryptographyClient"/> is cached per versioned key URI, with no eviction: a
/// versioned key URI's underlying key material never changes once minted, so a cached client for
/// a given URI never goes stale.
/// </remarks>
internal sealed class KeyVaultSigner : IKeyVaultSigner
{
    private static readonly IReadOnlyDictionary<SigningAlgorithm, SignatureAlgorithm> AlgorithmMap =
        new Dictionary<SigningAlgorithm, SignatureAlgorithm>
        {
            [SigningAlgorithm.RS256] = SignatureAlgorithm.RS256,
            [SigningAlgorithm.RS384] = SignatureAlgorithm.RS384,
            [SigningAlgorithm.RS512] = SignatureAlgorithm.RS512,
            [SigningAlgorithm.PS256] = SignatureAlgorithm.PS256,
            [SigningAlgorithm.PS384] = SignatureAlgorithm.PS384,
            [SigningAlgorithm.PS512] = SignatureAlgorithm.PS512,
            [SigningAlgorithm.ES256] = SignatureAlgorithm.ES256,
            [SigningAlgorithm.ES384] = SignatureAlgorithm.ES384,
            [SigningAlgorithm.ES512] = SignatureAlgorithm.ES512,
        };

    private readonly TokenCredential _credential;
    private readonly ConcurrentDictionary<Uri, CryptographyClient> _clients = new();

    public KeyVaultSigner(IOptions<AzureKeyVaultRemoteSigningOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var credential = options.Value.Credential;
        ArgumentNullException.ThrowIfNull(credential);

        _credential = credential;
    }

    /// <inheritdoc/>
    public async ValueTask<ReadOnlyMemory<byte>> SignAsync(
        Uri keyVersionUri, string keyLabel, SigningAlgorithm algorithm, byte[] signingInput, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(keyVersionUri);
        ArgumentException.ThrowIfNullOrEmpty(keyLabel);
        ArgumentNullException.ThrowIfNull(signingInput);

        var client = _clients.GetOrAdd(keyVersionUri, uri => new CryptographyClient(uri, _credential));
        var azureAlgorithm = ResolveAlgorithm(algorithm);

        try
        {
            var result = await client.SignDataAsync(azureAlgorithm, signingInput, cancellationToken)
                .ConfigureAwait(false);
            return result.Signature;
        }
        catch (RequestFailedException ex) when (ex.Status == 429)
        {
            throw new AzureKeyVaultSigningException(BuildThrottlingMessage(keyLabel, ex), ex);
        }
        catch (RequestFailedException ex)
        {
            throw new AzureKeyVaultSigningException(
                $"Key Vault signing request for key version '{keyLabel}' failed (HTTP {ex.Status}" +
                (ex.ErrorCode is null ? "" : $", ErrorCode: {ex.ErrorCode}") + ").",
                ex);
        }
    }

    private static SignatureAlgorithm ResolveAlgorithm(SigningAlgorithm algorithm) =>
        AlgorithmMap.TryGetValue(algorithm, out var mapped)
            ? mapped
            : throw new NotSupportedException(
                $"Signing algorithm {algorithm} has no Azure Key Vault SignatureAlgorithm mapping.");

    private static string BuildThrottlingMessage(string keyLabel, RequestFailedException ex)
    {
        var retryAfter = TryGetRetryAfter(ex);
        var retrySuffix = retryAfter is not null
            ? $" Retry after {retryAfter}."
            : " No Retry-After header was present on the response; back off and retry.";

        return $"Key Vault throttled the signing request for key version '{keyLabel}' (HTTP 429)." + retrySuffix;
    }

    private static string? TryGetRetryAfter(RequestFailedException ex)
    {
        var response = ex.GetRawResponse();
        return response is not null && response.Headers.TryGetValue("Retry-After", out var value)
            ? value
            : null;
    }
}
