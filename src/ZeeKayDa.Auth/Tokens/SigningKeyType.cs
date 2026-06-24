namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Identifies the cryptographic key type of a <see cref="SigningKeyDescriptor"/>.
/// </summary>
public enum SigningKeyType
{
    /// <summary>RSA key.</summary>
    Rsa,

    /// <summary>Elliptic-curve key.</summary>
    Ec,
}
