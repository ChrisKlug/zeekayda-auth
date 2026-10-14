using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// One PEM file's text, decoded into a pooled buffer that is wiped on <see cref="Dispose"/>, so the
/// private key material it may carry never sits on the heap in an immutable <see cref="string"/>.
/// </summary>
internal sealed class PemText : IDisposable
{
    private char[]? _buffer;
    private readonly int _length;

    private PemText(char[] buffer, int length, byte[] hash)
    {
        _buffer = buffer;
        _length = length;
        Hash = hash;
    }

    /// <summary>Gets the SHA-256 hash of the file's bytes, which identifies this version of the file.</summary>
    public byte[] Hash { get; }

    /// <summary>Gets the text. Valid until <see cref="Dispose"/>.</summary>
    public ReadOnlyMemory<char> Memory =>
        _buffer is { } buffer ? buffer.AsMemory(0, _length) : throw new ObjectDisposedException(nameof(PemText));

    /// <summary>Gets the text. Valid until <see cref="Dispose"/>.</summary>
    public ReadOnlySpan<char> Span => Memory.Span;

    /// <summary>Decodes <paramref name="bytes"/> as UTF-8 and wipes them.</summary>
    public static PemText Decode(byte[] bytes)
    {
        try
        {
            var length = Encoding.UTF8.GetCharCount(bytes);
            var buffer = ArrayPool<char>.Shared.Rent(length);
            Encoding.UTF8.GetChars(bytes, buffer);
            return new PemText(buffer, length, SHA256.HashData(bytes));
        }
        finally
        {
            bytes.AsSpan().Clear();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _buffer, null) is not { } buffer)
            return;

        buffer.AsSpan().Clear();
        ArrayPool<char>.Shared.Return(buffer);
    }
}
