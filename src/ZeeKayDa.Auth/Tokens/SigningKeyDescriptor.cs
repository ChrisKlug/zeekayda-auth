using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Carries the public identity and key material of a currently trusted signing key.
/// </summary>
/// <remarks>
/// <para>
/// A descriptor holds only the public-key parameters needed to publish the key in a JWKS and
/// to build a JWK wire representation. Private key material is never exposed here; it remains
/// inside the <see cref="IJwtSigningService"/> implementation.
/// </para>
/// <para>
/// The <see cref="Kid"/> is stable for the entire lifetime of the key. Once assigned it never
/// changes, so relying parties can match a token header <c>kid</c> to a JWKS entry
/// deterministically.
/// </para>
/// </remarks>
public sealed class SigningKeyDescriptor
{
    /// <summary>
    /// Initialises an RSA signing key descriptor.
    /// </summary>
    /// <param name="kid">
    /// The stable key identifier. Must be non-null and non-empty.
    /// </param>
    /// <param name="algorithm">
    /// The signing algorithm. Must be an RSA algorithm (RS256, RS384, RS512, PS256, PS384, PS512).
    /// </param>
    /// <param name="rsaPublicParameters">
    /// The RSA public parameters (exponent and modulus only — no private components).
    /// </param>
    public SigningKeyDescriptor(string kid, SigningAlgorithm algorithm, RSAParameters rsaPublicParameters)
    {
        ArgumentException.ThrowIfNullOrEmpty(kid);
        ValidateRsaAlgorithm(algorithm);

        Kid = kid;
        Algorithm = algorithm;
        RsaPublicParameters = rsaPublicParameters;
        KeyType = SigningKeyType.Rsa;
    }

    /// <summary>
    /// Initialises an EC signing key descriptor.
    /// </summary>
    /// <param name="kid">
    /// The stable key identifier. Must be non-null and non-empty.
    /// </param>
    /// <param name="algorithm">
    /// The signing algorithm. Must be an EC algorithm (ES256, ES384, ES512).
    /// </param>
    /// <param name="ecPublicParameters">
    /// The EC public parameters (curve and Q point — no private D component).
    /// </param>
    public SigningKeyDescriptor(string kid, SigningAlgorithm algorithm, ECParameters ecPublicParameters)
    {
        ArgumentException.ThrowIfNullOrEmpty(kid);
        ValidateEcAlgorithm(algorithm);

        Kid = kid;
        Algorithm = algorithm;
        EcPublicParameters = ecPublicParameters;
        KeyType = SigningKeyType.Ec;
    }

    /// <summary>Gets the stable key identifier.</summary>
    public string Kid { get; }

    /// <summary>Gets the signing algorithm associated with this key.</summary>
    public SigningAlgorithm Algorithm { get; }

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

    private static void ValidateRsaAlgorithm(SigningAlgorithm algorithm)
    {
        if (algorithm is not (SigningAlgorithm.RS256 or SigningAlgorithm.RS384 or SigningAlgorithm.RS512
            or SigningAlgorithm.PS256 or SigningAlgorithm.PS384 or SigningAlgorithm.PS512))
        {
            throw new ArgumentException(
                $"Algorithm {algorithm} is not an RSA algorithm. Use an EC algorithm constructor overload for EC keys.",
                nameof(algorithm));
        }
    }

    private static void ValidateEcAlgorithm(SigningAlgorithm algorithm)
    {
        if (algorithm is not (SigningAlgorithm.ES256 or SigningAlgorithm.ES384 or SigningAlgorithm.ES512))
        {
            throw new ArgumentException(
                $"Algorithm {algorithm} is not an EC algorithm. Use an RSA algorithm constructor overload for RSA keys.",
                nameof(algorithm));
        }
    }
}
