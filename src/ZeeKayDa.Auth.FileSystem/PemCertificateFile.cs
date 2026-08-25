namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// One PEM certificate configured into a published-only <see cref="PemFileSigningOptions"/> slot —
/// <see cref="PemFileSigningOptions.Previous"/> or <see cref="PemFileSigningOptions.Next"/>.
/// </summary>
/// <param name="Path">
/// The certificate's path. A combined cert+key file is accepted, but only its certificate block is
/// ever read.
/// </param>
/// <remarks>
/// <para>
/// Deliberately carries no private-key path, unlike <see cref="PemSigningFile"/>. Only the
/// <see cref="PemFileSigningOptions.Current"/> slot ever has its private key opened, so naming one
/// for a published-only slot could never do anything except leave a file the framework promises to
/// permission-check but never opens. Making it unrepresentable is what keeps that promise true.
/// </para>
/// <para>
/// Promoting a staged key is therefore not an assignment: a slot that starts signing needs its
/// private key named for the first time, as a <see cref="PemSigningFile"/>. Demoting the key it
/// succeeds drops that name again, so the outgoing key's private material stops being configured at
/// the moment it stops signing.
/// </para>
/// </remarks>
public sealed record PemCertificateFile(string Path);
