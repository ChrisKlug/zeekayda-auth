using System.Buffers.Text;
using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Default <see cref="IHandleGenerator"/> implementation backed by
/// <see cref="RandomNumberGenerator"/>.
/// </summary>
internal sealed class RandomHandleGenerator : IHandleGenerator
{
    private const int ByteCount = 32; // 256-bit output — exceeds the 128-bit minimum

    /// <inheritdoc/>
    public string Generate()
    {
        var bytes = RandomNumberGenerator.GetBytes(ByteCount);
        return Base64Url.EncodeToString(bytes);
    }
}
