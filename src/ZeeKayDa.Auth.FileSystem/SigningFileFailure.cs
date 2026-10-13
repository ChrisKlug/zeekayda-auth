using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>The failure a file source reports for one configured file that could not be listed.</summary>
internal static class SigningFileFailure
{
    /// <summary>
    /// <paramref name="exception"/>'s own failure, or for any other exception — a locked file, an I/O
    /// error, a password source that failed — <c>signing.file_signing.unreadable_file</c> naming its type.
    /// Every such failure is about this one file, so it must not hold up the rest of the read.
    /// </summary>
    public static SourceKeyFailure Of(string path, Exception exception) =>
        new(
            new SourceKeyId(path),
            exception is ZeeKayDaConfigurationException configuration
                ? configuration.AggregatedFailures[0]
                // The exception TYPE is named, never its message: it can echo a password or file content.
                : new ZeeKayDaConfigurationFailure(
                    "signing.file_signing.unreadable_file",
                    $"Signing key file '{path}' could not be read: {exception.GetType().FullName} was thrown."));
}
