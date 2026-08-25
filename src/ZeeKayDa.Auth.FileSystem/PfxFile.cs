namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// One PFX/PKCS#12 file configured into a <see cref="PfxFileSigningOptions"/> slot, with the delegate
/// that supplies its password.
/// </summary>
/// <param name="Path">The bundle's path.</param>
/// <param name="PasswordSource">
/// Supplies this bundle's password. Async and cancellable rather than a plain <see langword="string"/>
/// so a password can come from an environment variable, a file, or a remote secret store without
/// blocking a thread or sitting inline in configuration. Real-world bundles are frequently
/// password-per-file, so every slot carries its own.
/// </param>
/// <remarks>
/// <para>
/// Invoked once per configured slot when the source reads its slots at startup, and once more for
/// <see cref="PfxFileSigningOptions.Current"/> when its signer is opened. An implementation sourcing
/// the password from a slow or remote location should cache it itself.
/// </para>
/// <para>
/// Unlike PEM, there is one slot type here rather than two, and it is named for the file rather than
/// for signing — two of the three slots never sign. A PEM published-only slot drops its private-key
/// path, which is what makes opening one impossible; a PFX file has nothing to drop, since every slot
/// needs its path and password even to read a certificate. What keeps a published-only slot's private
/// key out of reach is how the file is read, not what is configured: see
/// <see cref="PfxFileSigningKeySource"/>.
/// </para>
/// </remarks>
public sealed record PfxFile(string Path, Func<CancellationToken, ValueTask<string>> PasswordSource);
