namespace ZeeKayDa.Auth.FileSystem;

/// <summary>Fetches a signing file's password from the host's password source.</summary>
internal static class SigningFilePassword
{
    /// <summary>
    /// What <paramref name="source"/> returns. A <see langword="null"/> password, and whatever it throws
    /// but a cancellation, is <c>signing.file_signing.password_unavailable</c>, naming only the exception
    /// type: the callback is host code, and its message may carry the secret it failed to fetch.
    /// </summary>
    public static async Task<string> ReadAsync(
        string path, Func<CancellationToken, Task<string>> source, CancellationToken cancellationToken)
    {
        string? password;
        try
        {
            password = await source(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.file_signing.password_unavailable",
                    $"The password source for '{path}' failed: {ex.GetType().FullName} was thrown. See " +
                    "the inner exception for the root cause."),
                ex);
        }

        return password ?? throw new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.file_signing.password_unavailable",
                $"The password source for '{path}' returned null."));
    }
}
