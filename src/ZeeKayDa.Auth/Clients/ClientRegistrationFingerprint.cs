using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Produces a stable content fingerprint of an <see cref="IClientRegistration"/>, used by
/// <see cref="ValidatedClientResolver"/> as the memoization key for a validation verdict.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Every security-relevant member of <see cref="IClientRegistration"/> and
/// <see cref="IClientMetadata"/> MUST be represented here.</strong> A member the fingerprint
/// omits can be changed without invalidating a cached verdict, which means a registration that
/// validation would now reject keeps being served as valid. When adding a member to either
/// interface, add it to <see cref="Compute"/> in the same change —
/// <c>ClientRegistrationFingerprintTests.Fingerprint_covers_every_IClientRegistration_member</c>
/// fails the build if you do not.
/// </para>
/// <para>
/// Fingerprinting is deliberately cheap: it reads already-derived values (a stored PBKDF2 hash is
/// read, never recomputed) so that it can run on every client lookup, unlike
/// <see cref="IClientRegistrationValidator"/> which performs a full key derivation.
/// </para>
/// </remarks>
internal static class ClientRegistrationFingerprint
{
    // Separators are control characters that cannot occur in any fingerprinted value, so no
    // combination of values can be re-partitioned into a different but equal-looking record.
    private const char FieldSeparator = '\u001f';
    // Distinguishes "no restriction" (null) from an empty set, which validate differently.
    private const string NullSentinel = "\u0000null";

    /// <summary>
    /// Returns a hex SHA-256 digest over every security-relevant value of
    /// <paramref name="client"/>. Two registrations with equal content produce equal
    /// fingerprints regardless of instance identity; any change to a covered value produces a
    /// different fingerprint.
    /// </summary>
    public static string Compute(IClientRegistration client)
    {
        var builder = new StringBuilder();

        // Field separators are characters that cannot appear in the values themselves, so no
        // combination of values can be re-partitioned into a different but equal-looking record.
        Append(builder, "id", client.ClientId);
        Append(builder, "public", client.IsPublic ? "1" : "0");
        Append(builder, "zkderr", client.EnableZkdErrorCodes ? "1" : "0");
        AppendSet(builder, "redirect", client.RedirectUris);
        AppendSet(builder, "postlogout", client.PostLogoutRedirectUris);
        AppendSet(builder, "scopes", client.AllowedScopes);
        AppendSet(builder, "authmethods", client.AllowedTokenEndpointAuthMethods);
        AppendSet(builder, "grants", client.AllowedGrantTypes.Select(v => v.ToString()));
        AppendSet(builder, "responsetypes", client.AllowedResponseTypes.Select(v => v.ToString()));
        AppendSet(builder, "responsemodes", client.AllowedResponseModes.Select(v => v.ToString()));
        AppendSet(builder, "prompts", client.AllowedPromptValues.Select(v => v.ToString()));
        AppendSet(
            builder,
            "algs",
            client.AllowedSigningAlgorithms is null
                ? [NullSentinel]
                : client.AllowedSigningAlgorithms.Select(v => v.ToString()));
        AppendCredentials(builder, client.Credentials);

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())));
    }

    private static void Append(StringBuilder builder, string name, string value) =>
        builder.Append(name).Append(FieldSeparator).Append(value).Append(FieldSeparator);

    private static void AppendSet(StringBuilder builder, string name, IEnumerable<string> values)
    {
        builder.Append(name).Append(FieldSeparator);

        // Sets are unordered, so a stable fingerprint requires a deterministic order. Ordinal
        // sorting is used rather than the set's own comparer, which is not trusted (see the
        // IClientMetadata string-set invariant).
        foreach (var value in values.OrderBy(v => v, StringComparer.Ordinal))
            builder.Append(value).Append(FieldSeparator);

        builder.Append(FieldSeparator);
    }

    private static void AppendCredentials(StringBuilder builder, IReadOnlyList<IClientCredential> credentials)
    {
        builder.Append("credentials").Append(FieldSeparator);

        // Credential order is meaningful to the validator's two-credential cap, so it is not
        // sorted away.
        foreach (var credential in credentials)
        {
            builder.Append(credential.GetType().FullName).Append(FieldSeparator);

            if (credential is IPbkdf2ClientSecret pbkdf2)
            {
                // Reads the stored digest; never derives one.
                builder
                    .Append(pbkdf2.Iterations).Append(FieldSeparator)
                    .Append(Convert.ToHexStringLower(pbkdf2.Salt)).Append(FieldSeparator)
                    .Append(Convert.ToHexStringLower(pbkdf2.Hash));
            }
            else
            {
                // IClientCredential is a marker interface with no members, so a custom credential
                // type exposes nothing to fingerprint by content. Falling back to instance
                // identity keeps the verdict correct — a mutated credential is a different
                // fingerprint only if the instance changed — at the cost of revalidating when a
                // store hands out fresh instances. That is exactly the behaviour every
                // registration had before fingerprinting, so this is never a regression; it just
                // does not get the improvement.
                builder.Append(RuntimeHelpers.GetHashCode(credential));
            }

            builder.Append(FieldSeparator);
        }

        builder.Append(FieldSeparator);
    }
}
