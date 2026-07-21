using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Public-only key parameters carried by a <see cref="KeyListing"/> — the same public material
/// <see cref="SigningKeyDescriptor"/> carries, minus the <c>kid</c> and algorithm (those live on
/// <see cref="KeyListing"/> itself).
/// </summary>
/// <remarks>
/// Never carries private key material. A provider builds an instance from an <see cref="RSA"/> or
/// <see cref="ECDsa"/> object's exported public parameters via <see cref="FromRsa"/>/<see cref="FromEc"/>
/// without ever exposing the private half through this type.
/// </remarks>
public sealed record PublicKeyParameters
{
    private PublicKeyParameters(SigningKeyType keyType, RSAParameters? rsaPublicParameters, ECParameters? ecPublicParameters)
    {
        KeyType = keyType;
        RsaPublicParameters = rsaPublicParameters;
        EcPublicParameters = ecPublicParameters;
    }

    /// <summary>Gets the key type (RSA or EC).</summary>
    public SigningKeyType KeyType { get; }

    /// <summary>
    /// Gets the RSA public parameters when <see cref="KeyType"/> is <see cref="SigningKeyType.Rsa"/>;
    /// otherwise <see langword="null"/>.
    /// </summary>
    public RSAParameters? RsaPublicParameters { get; }

    /// <summary>
    /// Gets the EC public parameters when <see cref="KeyType"/> is <see cref="SigningKeyType.Ec"/>;
    /// otherwise <see langword="null"/>.
    /// </summary>
    public ECParameters? EcPublicParameters { get; }

    /// <summary>
    /// Builds an RSA <see cref="PublicKeyParameters"/> from the exponent and modulus only.
    /// </summary>
    /// <param name="rsaPublicParameters">
    /// The RSA public parameters (exponent and modulus only — no private components).
    /// </param>
    public static PublicKeyParameters FromRsa(RSAParameters rsaPublicParameters) =>
        new(SigningKeyType.Rsa, rsaPublicParameters, ecPublicParameters: null);

    /// <summary>
    /// Builds an EC <see cref="PublicKeyParameters"/> from the curve and Q point only.
    /// </summary>
    /// <param name="ecPublicParameters">
    /// The EC public parameters (curve and Q point — no private D component).
    /// </param>
    public static PublicKeyParameters FromEc(ECParameters ecPublicParameters) =>
        new(SigningKeyType.Ec, rsaPublicParameters: null, ecPublicParameters);
}
