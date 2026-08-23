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
    private readonly RSAParameters? _rsaPublicParameters;
    private readonly ECParameters? _ecPublicParameters;

    private PublicKeyParameters(SigningKeyType keyType, RSAParameters? rsaPublicParameters, ECParameters? ecPublicParameters)
    {
        KeyType = keyType;
        _rsaPublicParameters = rsaPublicParameters;
        _ecPublicParameters = ecPublicParameters;
    }

    /// <summary>Gets the key type (RSA or EC).</summary>
    public SigningKeyType KeyType { get; }

    /// <summary>
    /// Gets the RSA public parameters when <see cref="KeyType"/> is <see cref="SigningKeyType.Rsa"/>;
    /// otherwise <see langword="null"/>.
    /// </summary>
    /// <remarks>
    /// Returns a fresh defensive copy on every access. The framework's own copy of <c>Modulus</c>
    /// and <c>Exponent</c> is never handed out by reference, so a caller mutating the returned
    /// arrays can never corrupt the key material this instance — or a <see cref="SigningKey"/> built
    /// from it — actually holds.
    /// </remarks>
    public RSAParameters? RsaPublicParameters => CopyRsa(_rsaPublicParameters);

    /// <summary>
    /// Gets the EC public parameters when <see cref="KeyType"/> is <see cref="SigningKeyType.Ec"/>;
    /// otherwise <see langword="null"/>.
    /// </summary>
    /// <remarks>
    /// Returns a fresh defensive copy on every access, for the same reason as
    /// <see cref="RsaPublicParameters"/>.
    /// </remarks>
    public ECParameters? EcPublicParameters => CopyEc(_ecPublicParameters);

    /// <summary>
    /// Builds an RSA <see cref="PublicKeyParameters"/> from the exponent and modulus only.
    /// </summary>
    /// <param name="rsaPublicParameters">
    /// The RSA public parameters (exponent and modulus only — no private components).
    /// </param>
    public static PublicKeyParameters FromRsa(RSAParameters rsaPublicParameters)
    {
        var publicOnly = new RSAParameters
        {
            Modulus = rsaPublicParameters.Modulus!.ToArray(),
            Exponent = rsaPublicParameters.Exponent!.ToArray(),
        };

        return new(SigningKeyType.Rsa, publicOnly, ecPublicParameters: null);
    }

    /// <summary>
    /// Builds an EC <see cref="PublicKeyParameters"/> from the curve and Q point only.
    /// </summary>
    /// <param name="ecPublicParameters">
    /// The EC public parameters (curve and Q point — no private D component).
    /// </param>
    public static PublicKeyParameters FromEc(ECParameters ecPublicParameters)
    {
        var publicOnly = new ECParameters
        {
            Curve = ecPublicParameters.Curve,
            Q = new ECPoint
            {
                X = ecPublicParameters.Q.X!.ToArray(),
                Y = ecPublicParameters.Q.Y!.ToArray(),
            },
        };

        return new(SigningKeyType.Ec, rsaPublicParameters: null, publicOnly);
    }

    private static RSAParameters? CopyRsa(RSAParameters? source)
    {
        if (source is not { } value)
            return null;

        return new RSAParameters
        {
            Modulus = value.Modulus?.ToArray(),
            Exponent = value.Exponent?.ToArray(),
        };
    }

    private static ECParameters? CopyEc(ECParameters? source)
    {
        if (source is not { } value)
            return null;

        return new ECParameters
        {
            Curve = value.Curve,
            Q = new ECPoint
            {
                X = value.Q.X?.ToArray(),
                Y = value.Q.Y?.ToArray(),
            },
        };
    }
}
