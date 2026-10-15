using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The public material of a <see cref="SourceKey"/>, without the <c>kid</c> and algorithm.
/// </summary>
/// <remarks>
/// Never carries private key material: <see cref="FromRsa"/> and <see cref="FromEc"/> copy the public
/// parameters only.
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
    /// A fresh copy on every access, so a caller mutating it cannot corrupt the key material held here.
    /// </remarks>
    public RSAParameters? RsaPublicParameters => CopyRsa(_rsaPublicParameters);

    /// <summary>
    /// Gets the EC public parameters when <see cref="KeyType"/> is <see cref="SigningKeyType.Ec"/>;
    /// otherwise <see langword="null"/>.
    /// </summary>
    /// <remarks>
    /// A fresh copy on every access, as for <see cref="RsaPublicParameters"/>.
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
