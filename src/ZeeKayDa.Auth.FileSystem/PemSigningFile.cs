namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// The PEM certificate configured into <see cref="PemFileSigningOptions.Current"/> — the one slot
/// whose private key is ever opened.
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
/// The published-only slots take a <see cref="PemCertificateFile"/> instead, which has no
/// <see cref="KeyPath"/> at all. Both paths here are validated by
/// <see cref="PemFileSigningOptionsValidator"/> at startup rather than on assignment, so a
/// configuration-bound options instance reports every problem at once instead of throwing from the
/// first bad property setter.
/// </remarks>
public sealed record PemSigningFile(string Path, string? KeyPath = null);
