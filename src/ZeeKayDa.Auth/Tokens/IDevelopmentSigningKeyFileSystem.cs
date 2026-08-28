namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Abstracts OS-specific file-system operations needed by the development signing key provider.
/// </summary>
/// <remarks>
/// The default implementation, <see cref="LocalSigningKeyFileSystem"/>, calls real OS APIs
/// (Unix file-mode bits, Windows ACLs) and is tested directly against real temp directories by
/// <c>LocalSigningKeyFileSystemTests</c>, with each assertion gated to the platform whose
/// permission model it describes. This interface exists so that
/// <see cref="DevelopmentSigningKeySource"/>'s own logic — the environment gate, the
/// generate-vs-load decision, the ephemeral path that must never touch disk at all — can be tested
/// with fakes that go nowhere near the file system, not because the real implementation is
/// untestable.
/// </remarks>
internal interface IDevelopmentSigningKeyFileSystem
{
    /// <summary>
    /// Ensures the given directory exists and is accessible only by the current user, creating it —
    /// and every missing component above it — with restrictive permissions if it does not yet exist.
    /// </summary>
    /// <remarks>
    /// Throws <see cref="ZeeKayDaConfigurationException"/> when the directory itself has permissions
    /// broader than expected, and also when any component of its path fails validation: one owned by
    /// another user, one whose ownership cannot be read, a symlink, a component writable by group or
    /// other without the sticky bit, or an entry that exists but is not a directory. The walk stops
    /// at the first root-owned component, which is treated as OS-managed and trusted.
    /// </remarks>
    /// <param name="directory">The directory path to create or validate.</param>
    void EnsureDirectorySafe(string directory);

    /// <summary>
    /// Writes <paramref name="pem"/> to <paramref name="keyPath"/> with restrictive permissions
    /// so that only the current user can read the file.
    /// </summary>
    /// <param name="keyPath">The file path to write.</param>
    /// <param name="pem">
    /// The PEM-encoded key material as a char buffer. Callers should rent a <c>char[]</c>
    /// from <see cref="System.Buffers.ArrayPool{T}"/>, write the PEM into it, pass it here,
    /// then zero and return the array so that private key material does not linger on the heap.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    ValueTask WriteKeyFileAsync(string keyPath, ReadOnlyMemory<char> pem, CancellationToken cancellationToken);

    /// <summary>
    /// Reads the PEM content from <paramref name="keyPath"/> as a UTF-8 byte array.
    /// Throws <see cref="ZeeKayDaConfigurationException"/> if the file resolves through a
    /// symlink or has permissions broader than expected.
    /// </summary>
    /// <param name="keyPath">The file path to read.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// A <see cref="KeyFileContent"/> wrapping the raw PEM bytes. The caller must dispose it
    /// promptly after the key has been imported so that key material is zeroed on the heap.
    /// </returns>
    ValueTask<KeyFileContent> ReadKeyFileAsync(string keyPath, CancellationToken cancellationToken);

    /// <summary>
    /// Returns <see langword="true"/> if a file exists at <paramref name="path"/>.
    /// </summary>
    /// <param name="path">The file path to test.</param>
    bool FileExists(string path);
}
