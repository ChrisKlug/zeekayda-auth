namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Abstracts OS-specific file-system operations needed by the development signing key provider.
/// </summary>
/// <remarks>
/// The default implementation, <see cref="OsSigningKeyFileSystem"/>, calls real OS APIs
/// (Unix file-mode bits, Windows ACLs). Tests substitute a fake implementation so that
/// platform-specific code paths are never exercised on the test runner's OS.
/// </remarks>
internal interface ISigningKeyFileSystem
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
    /// <param name="pem">The PEM-encoded key material.</param>
    void WriteKeyFile(string keyPath, string pem);

    /// <summary>
    /// Reads the PEM content from <paramref name="keyPath"/>.
    /// Throws <see cref="ZeeKayDaConfigurationException"/> if the file resolves through a
    /// symlink or has permissions broader than expected.
    /// </summary>
    /// <param name="keyPath">The file path to read.</param>
    /// <returns>The raw PEM content of the file.</returns>
    string ReadKeyFile(string keyPath);

    /// <summary>
    /// Returns <see langword="true"/> if a file exists at <paramref name="path"/>.
    /// </summary>
    /// <param name="path">The file path to test.</param>
    bool FileExists(string path);
}
