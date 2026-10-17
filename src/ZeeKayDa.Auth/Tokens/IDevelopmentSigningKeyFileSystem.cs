namespace ZeeKayDa.Auth.Tokens;

/// <summary>The OS file-system operations the development signing key source needs, so its own logic can be tested with fakes.</summary>
internal interface IDevelopmentSigningKeyFileSystem
{
    /// <summary>
    /// Creates <paramref name="directory"/> and any missing parents owner-only, with a <c>.gitignore</c>
    /// ignoring everything in a directory it creates, and throws
    /// <see cref="ZeeKayDaConfigurationException"/> when it ends up broader than owner-only.
    /// </summary>
    /// <param name="directory">The directory path to create or validate.</param>
    void EnsureDirectorySafe(string directory);

    /// <summary>
    /// Writes <paramref name="pem"/> owner-only and atomically, unless a file is already there; of racing hosts, exactly one writes.
    /// </summary>
    /// <param name="keyPath">The file path to write.</param>
    /// <param name="pem">The PEM text, in a buffer the caller zeroes afterwards.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    ValueTask WriteKeyFileAsync(string keyPath, ReadOnlyMemory<char> pem, CancellationToken cancellationToken);

    /// <summary>
    /// Reads the PEM bytes, throwing <see cref="ZeeKayDaConfigurationException"/> for a symlink or broad permissions.
    /// </summary>
    /// <param name="keyPath">The file path to read.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The raw PEM bytes, which the caller disposes once the key is imported.</returns>
    ValueTask<KeyFileContent> ReadKeyFileAsync(string keyPath, CancellationToken cancellationToken);

    /// <summary>Whether a file exists at <paramref name="path"/>, directly or through a symlink; a dangling one counts as absent.</summary>
    /// <param name="path">The file path to test.</param>
    bool FileExists(string path);
}
