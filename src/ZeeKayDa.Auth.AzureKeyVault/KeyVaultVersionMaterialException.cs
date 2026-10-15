namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// A failure in one Key Vault version's own key material — an unsupported key type, material that
/// cannot be read. A read reports that version and lists the others; every other failure is about
/// the vault and fails the whole read.
/// </summary>
internal sealed class KeyVaultVersionMaterialException : ZeeKayDaConfigurationException
{
    public KeyVaultVersionMaterialException(ZeeKayDaConfigurationFailure failure)
        : base(failure)
    {
    }

    public KeyVaultVersionMaterialException(ZeeKayDaConfigurationFailure failure, Exception innerException)
        : base(failure, innerException)
    {
    }
}
