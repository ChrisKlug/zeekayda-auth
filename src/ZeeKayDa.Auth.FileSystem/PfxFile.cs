namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// One PFX/PKCS#12 bundle listed in <see cref="PfxFileSigningOptions.Files"/>, with the delegate that
/// supplies its password.
/// </summary>
/// <param name="Path">The bundle's path. It is also the key's identifier in every configuration
/// failure about it.</param>
/// <param name="PasswordSource">
/// Supplies this bundle's password. Async and cancellable rather than a plain <see langword="string"/>
/// so a password can come from an environment variable, a file, or a remote secret store without
/// blocking a thread or sitting inline in configuration. Real-world bundles are frequently
/// password-per-file, so every bundle carries its own.
/// </param>
/// <remarks>
/// Invoked once per listed bundle when the source lists its keys at startup, and once more for the
/// bundle chosen to sign. An implementation sourcing the password from a slow or remote location
/// should cache it itself.
/// </remarks>
public sealed record PfxFile(string Path, Func<CancellationToken, Task<string>> PasswordSource);
