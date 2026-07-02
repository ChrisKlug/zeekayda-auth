namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Abstracts OS-specific file-system operations needed by the development signing key provider.
/// </summary>
/// <remarks>
/// The default implementation, <see cref="LocalSigningKeyFileSystem"/>, calls real OS APIs
/// (Unix file-mode bits, Windows ACLs). Tests substitute a fake implementation so that
/// platform-specific code paths are never exercised on the test runner's OS.
/// </remarks>
internal interface IDevelopmentSigningKeyFileSystem
{
    /// <summary>
    /// Ensures the given directory exists and is accessible only by the current user.
    /// Creates it with restrictive permissions if it does not yet exist.
    /// Throws <see cref="ZeeKayDaConfigurationException"/> if the directory already exists
    /// but its permissions are broader than expected.
    /// </summary>
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
