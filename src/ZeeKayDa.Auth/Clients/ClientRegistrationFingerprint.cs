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
    // Every value is length-prefixed rather than delimited. A separator alone is not enough:
    // values reach this type straight from the store, *before* validation, so one containing the
    // separator could make two different registrations serialize identically — and a collision
    // means an invalid registration inheriting a valid one's verdict.
    private const char FieldSeparator = '\u001f';
    // Distinguishes "no restriction" (null) from an empty set, which validate differently.
    private const string NullSentinel = "\u0000null";

    /// <summary>
    /// Returns a hex SHA-256 digest over every security-relevant value of
    /// <paramref name="client"/>. Two registrations with equal content produce equal
    /// fingerprints regardless of instance identity; any change to a covered value produces a
    /// different fingerprint.
    /// </summary>
    public static Fingerprint Compute(IClientRegistration client)
    {
        var builder = new StringBuilder();
        var contentAddressable = true;

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
        contentAddressable = AppendCredentials(builder, client.Credentials);

        return new Fingerprint(
            Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString()))),
            contentAddressable);
    }

    private static void Append(StringBuilder builder, string name, string value)
    {
        AppendLengthPrefixed(builder, name);
        AppendLengthPrefixed(builder, value);
    }

    /// <summary>Writes <c>{length}:{value}</c> so no value can be mistaken for a boundary.</summary>
    private static void AppendLengthPrefixed(StringBuilder builder, string value) =>
        builder.Append(value.Length).Append(':').Append(value).Append(FieldSeparator);

    private static void AppendSet(StringBuilder builder, string name, IEnumerable<string> values)
    {
        AppendLengthPrefixed(builder, name);

        // Sets are unordered, so a stable fingerprint requires a deterministic order. Ordinal
        // sorting is used rather than the set's own comparer, which is not trusted (see the
        // IClientMetadata string-set invariant). The count is written too, so a set cannot be
        // confused with a differently-sized one whose members concatenate the same way.
        var ordered = values.OrderBy(v => v, StringComparer.Ordinal).ToList();
        builder.Append(ordered.Count).Append(FieldSeparator);

        foreach (var value in ordered)
            AppendLengthPrefixed(builder, value);
    }

    /// <summary>
    /// Returns <see langword="false"/> when any credential had to fall back to instance identity,
    /// which makes the resulting fingerprint unrepeatable across instances and therefore unsafe
    /// to cache under.
    /// </summary>
    private static bool AppendCredentials(StringBuilder builder, IReadOnlyList<IClientCredential> credentials)
    {
        var contentAddressable = true;
        AppendLengthPrefixed(builder, "credentials");
        builder.Append(credentials.Count).Append(FieldSeparator);

        // Credential order is meaningful to the validator's two-credential cap, so it is not
        // sorted away.
        foreach (var credential in credentials)
        {
            AppendLengthPrefixed(builder, credential.GetType().FullName ?? string.Empty);

            if (credential is IPbkdf2ClientSecret pbkdf2)
            {
                // Reads the stored digest; never derives one.
                builder.Append(pbkdf2.Iterations).Append(FieldSeparator);
                AppendLengthPrefixed(builder, Convert.ToHexStringLower(pbkdf2.Salt));
                AppendLengthPrefixed(builder, Convert.ToHexStringLower(pbkdf2.Hash));
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
                builder.Append(RuntimeHelpers.GetHashCode(credential)).Append(FieldSeparator);
                contentAddressable = false;
            }
        }

        return contentAddressable;
    }

    /// <summary>
    /// A registration's content digest, and whether it is reproducible from content alone.
    /// </summary>
    /// <param name="Value">The hex SHA-256 digest.</param>
    /// <param name="IsContentAddressable">
    /// <see langword="false"/> when a custom <see cref="IClientCredential"/> forced an
    /// instance-identity fallback. Such a fingerprint differs for every instance of the same
    /// registration, so caching under it would fill the cache with keys that can never be hit
    /// again — request-driven growth, which is exactly what the cache bound must not depend on.
    /// </param>
    internal readonly record struct Fingerprint(string Value, bool IsContentAddressable);
}
