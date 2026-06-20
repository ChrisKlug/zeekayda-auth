namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Generates cryptographically random opaque handle strings for authorization codes and
/// refresh tokens.
/// </summary>
/// <remarks>
/// All implementations MUST use <see cref="System.Security.Cryptography.RandomNumberGenerator"/>
/// or equivalent CSPRNG. <c>System.Random</c>, <c>Guid.NewGuid()</c>, and
/// <c>Random.Shared</c> are prohibited on this path. Generated handles must carry at
/// least 128 bits of entropy; the default implementation uses 32 bytes (256 bits),
/// producing Base64Url-encoded strings of at least 43 characters.
/// </remarks>
public interface IHandleGenerator
{
    /// <summary>
    /// Generates a new cryptographically random opaque handle string.
    /// </summary>
    /// <returns>
    /// A Base64Url-encoded string backed by at least 128 bits of CSPRNG entropy
    /// (&#x2265; 43 characters).
    /// </returns>
    string Generate();
}
