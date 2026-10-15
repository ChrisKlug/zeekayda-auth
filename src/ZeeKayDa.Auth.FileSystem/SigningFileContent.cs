namespace ZeeKayDa.Auth.FileSystem;

/// <summary>What a signing file carries, which decides the permissions <see cref="FileSigningKeyReader"/> allows on it.</summary>
internal enum SigningFileContent
{
    /// <summary>A private key, alone or beside its certificate: readable and writable by its owner only.</summary>
    PrivateKey,

    /// <summary>A certificate and no private key: anyone may read it, only its owner may write it.</summary>
    CertificateOnly,
}
