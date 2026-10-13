namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// One PEM file listed in <see cref="PemFileSigningOptions.Files"/>.
/// </summary>
/// <param name="Path">
/// The certificate's path — a combined cert+key file when <paramref name="KeyPath"/> is
/// <see langword="null"/>, otherwise the certificate-only file. It is also the key's identifier in
/// every configuration failure about it.
/// </param>
/// <param name="KeyPath">
/// The separate private-key-only file's path, or <see langword="null"/> when
/// <paramref name="Path"/> is a combined cert+key file. The split form is the convention used by
/// Let's Encrypt/certbot (<c>fullchain.pem</c> + <c>privkey.pem</c>) and cert-manager.
/// </param>
/// <param name="PasswordSource">
/// Supplies the password of a PKCS#8-encrypted private key (an <c>ENCRYPTED PRIVATE KEY</c> block,
/// RFC 5958 §3), or <see langword="null"/> (the default) when the key is not encrypted. It applies to
/// whichever file carries the key. A key encrypted in the legacy OpenSSL format
/// (<c>Proc-Type: 4,ENCRYPTED</c>) is refused; convert it with <c>openssl pkcs8 -topk8</c>.
/// </param>
/// <remarks>
/// <para>
/// Both paths are validated by <see cref="PemFileSigningOptionsValidator"/> at startup rather than on
/// assignment, so a configuration-bound options instance reports every problem at once.
/// </para>
/// <para>
/// The password is invoked when listing first finds the file, again whenever the certificate or key
/// changes, and once for the file chosen to sign. An implementation sourcing it from a slow or remote
/// location should cache it itself. It is defense in depth against offline exposure of the key file —
/// backups, disk images, a permission slip — not against an attacker running as the process, who can
/// read wherever the password comes from as well.
/// </para>
/// </remarks>
public sealed record PemSigningFile(
    string Path,
    string? KeyPath = null,
    Func<CancellationToken, Task<string>>? PasswordSource = null);
