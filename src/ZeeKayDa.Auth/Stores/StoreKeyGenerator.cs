using System.Buffers.Text;
using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Generates cryptographically random, Base64Url-encoded store keys for authorization codes
/// and refresh tokens.
/// </summary>
/// <remarks>
/// All key generation uses <see cref="RandomNumberGenerator"/> (a CSPRNG). <c>System.Random</c>,
/// <c>Guid.NewGuid()</c>, and <c>Random.Shared</c> are prohibited on this path. Generated keys
/// carry 256 bits of entropy (32 bytes), producing Base64Url-encoded strings of 43 characters.
/// </remarks>
internal static class StoreKeyGenerator
{
    private const int ByteCount = 32; // 256-bit output — exceeds the 128-bit minimum

    /// <summary>
    /// Generates a new cryptographically random, Base64Url-encoded store key.
    /// </summary>
    /// <returns>
    /// A Base64Url-encoded string backed by 256 bits of CSPRNG entropy (43 characters).
    /// </returns>
    public static string Generate()
    {
        var bytes = RandomNumberGenerator.GetBytes(ByteCount);
        return Base64Url.EncodeToString(bytes);
    }
}
