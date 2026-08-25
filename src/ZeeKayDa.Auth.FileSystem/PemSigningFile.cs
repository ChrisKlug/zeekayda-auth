namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// One PEM certificate configured into a <see cref="PemFileSigningOptions"/> slot.
/// </summary>
/// <param name="Path">
/// The certificate's path — a combined cert+key file when <paramref name="KeyPath"/> is
/// <see langword="null"/>, otherwise the certificate-only file.
/// </param>
/// <param name="KeyPath">
/// The separate private-key-only file's path, or <see langword="null"/> when
/// <paramref name="Path"/> is a combined cert+key file. The split form is the convention used by
/// Let's Encrypt/certbot (<c>fullchain.pem</c> + <c>privkey.pem</c>) and cert-manager.
/// </param>
/// <remarks>
/// Both paths are validated by <see cref="PemFileSigningOptionsValidator"/> at startup rather than
/// on assignment, so a configuration-bound options instance reports every problem at once instead of
/// throwing from the first bad property setter.
/// </remarks>
public sealed record PemSigningFile(string Path, string? KeyPath = null);
