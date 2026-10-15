using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>The raw bytes of a signing key file, zeroed on disposal, which comes as soon as the key is imported.</summary>
internal sealed class KeyFileContent : IDisposable
{
    private readonly byte[] _bytes;
    private bool _disposed;

    internal KeyFileContent(byte[] bytes) => _bytes = bytes;

    /// <summary>
    /// Gets the raw PEM bytes read from the key file.
    /// </summary>
    /// <exception cref="ObjectDisposedException">
    /// Thrown if this instance has already been disposed.
    /// </exception>
    public ReadOnlySpan<byte> Bytes
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _bytes;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (!_disposed)
        {
            CryptographicOperations.ZeroMemory(_bytes);
            _disposed = true;
        }
    }
}
