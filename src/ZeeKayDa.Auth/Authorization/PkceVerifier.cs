using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// Proof Key for Code Exchange, server side: whether a presented <c>code_verifier</c> is the one
/// the stored <c>code_challenge</c> was derived from (RFC 7636 §4.6).
/// </summary>
internal static partial class PkceVerifier
{
    // RFC 7636 §4.1: 43–128 characters from the unreserved set.
    [GeneratedRegex("^[A-Za-z0-9\\-._~]{43,128}$")]
    private static partial Regex CodeVerifierPattern();

    /// <summary>Whether <paramref name="codeVerifier"/> has the shape RFC 7636 §4.1 gives it.</summary>
    public static bool IsWellFormed(string codeVerifier)
    {
        ArgumentNullException.ThrowIfNull(codeVerifier);
        return CodeVerifierPattern().IsMatch(codeVerifier);
    }

    /// <summary>
    /// Whether the challenge derived from <paramref name="codeVerifier"/> by the binding's method
    /// equals the binding's challenge. The comparison is fixed-time, and a method this verifier
    /// has no derivation for fails rather than passes.
    /// </summary>
    public static bool Verify(string codeVerifier, PkceChallenge pkce)
    {
        ArgumentNullException.ThrowIfNull(codeVerifier);
        ArgumentNullException.ThrowIfNull(pkce);

        if (pkce.Method != CodeChallengeMethod.S256)
            return false;

        Span<byte> digest = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier), digest);
        var derived = Base64Url.EncodeToString(digest);

        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(derived),
            Encoding.ASCII.GetBytes(pkce.Challenge));
    }
}
