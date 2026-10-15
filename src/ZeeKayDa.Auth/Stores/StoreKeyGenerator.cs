using System.Buffers.Text;
using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Stores;

/// <summary>Generates 256-bit CSPRNG handles, Base64Url-encoded, for authorization codes and refresh tokens.</summary>
internal static class StoreKeyGenerator
{
    private const int ByteCount = 32;

    /// <summary>A new 43-character handle.</summary>
    public static string Generate()
    {
        var bytes = RandomNumberGenerator.GetBytes(ByteCount);
        return Base64Url.EncodeToString(bytes);
    }
}
