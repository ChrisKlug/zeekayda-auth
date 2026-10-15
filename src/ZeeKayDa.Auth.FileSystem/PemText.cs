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
    private readonly ArrayPool<char> _pool;
    private readonly int _length;
    private readonly byte[] _hash;

    private PemText(ArrayPool<char> pool, char[] buffer, int length, byte[] hash)
    {
        _pool = pool;
        _buffer = buffer;
        _length = length;
        _hash = hash;
    }

    /// <summary>Gets the SHA-256 hash of the file's bytes, which identifies this version of the file.</summary>
    public ReadOnlySpan<byte> Hash => _hash;

    /// <summary>Gets the text. Valid until <see cref="Dispose"/>.</summary>
    public ReadOnlyMemory<char> Memory =>
        _buffer is { } buffer ? buffer.AsMemory(0, _length) : throw new ObjectDisposedException(nameof(PemText));

    /// <summary>Gets the text. Valid until <see cref="Dispose"/>.</summary>
    public ReadOnlySpan<char> Span => Memory.Span;

    /// <summary>Decodes <paramref name="bytes"/> as UTF-8 and wipes them.</summary>
    public static PemText Decode(byte[] bytes) => Decode(bytes, ArrayPool<char>.Shared);

    /// <summary><see cref="Decode(byte[])"/> renting from <paramref name="pool"/>.</summary>
    internal static PemText Decode(byte[] bytes, ArrayPool<char> pool)
    {
        char[]? buffer = null;
        try
        {
            var length = Encoding.UTF8.GetCharCount(bytes);
            buffer = pool.Rent(length);
            Encoding.UTF8.GetChars(bytes, buffer);
            return new PemText(pool, buffer, length, SHA256.HashData(bytes));
        }
        catch
        {
            if (buffer is not null)
            {
                buffer.AsSpan().Clear();
                pool.Return(buffer);
            }

            throw;
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
        _pool.Return(buffer);
    }
}
