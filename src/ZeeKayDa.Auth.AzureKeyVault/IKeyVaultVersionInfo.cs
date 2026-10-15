namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>The listing metadata of a Key Vault key or certificate version.</summary>
internal interface IKeyVaultVersionInfo
{
    /// <summary>The full versioned identifier URI.</summary>
    Uri Id { get; }

    /// <summary>The version segment.</summary>
    string Version { get; }

    /// <summary>Whether the version is enabled; a disabled version is unpublished at once.</summary>
    bool Enabled { get; }

    /// <summary>When Key Vault created the version; every replica reads the same value.</summary>
    DateTimeOffset CreatedOn { get; }

    /// <summary>The version's configured not-before time, if any.</summary>
    DateTimeOffset? NotBefore { get; }

    /// <summary>The version's configured expiry time, if any.</summary>
    DateTimeOffset? ExpiresOn { get; }
}
