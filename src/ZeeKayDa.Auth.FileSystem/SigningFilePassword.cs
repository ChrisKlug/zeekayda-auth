namespace ZeeKayDa.Auth.FileSystem;

/// <summary>Fetches a signing file's password from the host's password source.</summary>
internal static class SigningFilePassword
{
    /// <summary>
    /// What <paramref name="source"/> returns. A <see langword="null"/> or empty password, and whatever it
    /// throws but a cancellation, is <c>signing.file_signing.password_unavailable</c>, naming only the
    /// exception type: the callback is host code, and its message may carry the secret it failed to fetch.
    /// An empty password is most often a missing secret bound to <c>""</c>, and a key encrypted under it
    /// is a plain key in disguise.
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

        return password switch
        {
            null => throw Unavailable(path, "returned null"),
            "" => throw Unavailable(path, "returned an empty password"),
            _ => password,
        };
    }

    private static ZeeKayDaConfigurationException Unavailable(string path, string what) =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.file_signing.password_unavailable",
            $"The password source for '{path}' {what}."));
}
