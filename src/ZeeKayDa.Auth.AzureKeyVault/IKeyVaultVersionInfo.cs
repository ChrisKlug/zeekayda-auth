namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// The rotation-relevant metadata shared by every Key Vault "version-of-something" this package
/// signs with — currently <see cref="KeyVaultKeyVersionInfo"/> (a Key Vault key version) and
/// <see cref="KeyVaultCertificateVersionInfo"/> (a Key Vault certificate version). Lets
/// <see cref="KeyVaultSigningKeyRotation"/> derive the shared activation/retirement timeline logic
/// once, generically, instead of duplicating it per provider.
/// </summary>
internal interface IKeyVaultVersionInfo
{
    /// <summary>The full versioned identifier URI.</summary>
    Uri Id { get; }

    /// <summary>The version segment.</summary>
    string Version { get; }

    /// <summary>
    /// Whether the version is currently enabled. An operator disabling a version is an immediate,
    /// unconditional exclusion from the trusted key set, bypassing the retirement window.
    /// </summary>
    bool Enabled { get; }

    /// <summary>
    /// The durable creation timestamp Key Vault stamped on this version. Identical across every
    /// replica and process restart — the basis for the entire stateless rotation derivation.
    /// </summary>
    DateTimeOffset CreatedOn { get; }

    /// <summary>The version's configured not-before time, if any.</summary>
    DateTimeOffset? NotBefore { get; }

    /// <summary>The version's configured expiry time, if any.</summary>
    DateTimeOffset? ExpiresOn { get; }
}
