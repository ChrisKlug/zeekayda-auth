using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Produces a stable content fingerprint of an <see cref="IClientWithCredentials"/>, used by
/// <see cref="ValidatedClientResolver"/> as the memoization key for a validation verdict.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Every security-relevant member of <see cref="IClientWithCredentials"/> and
/// <see cref="IClient"/> MUST be represented here.</strong> A member the fingerprint
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
    public static string Compute(IClientWithCredentials client)
    {
        var builder = new StringBuilder();

        // Field separators are characters that cannot appear in the values themselves, so no
        // combination of values can be re-partitioned into a different but equal-looking record.
        Append(builder, "id", client.ClientId);
        Append(builder, "public", client.IsPublic ? "1" : "0");
        Append(builder, "zkderr", client.EnableZkdErrorCodes ? "1" : "0");
        Append(builder, "consent", client.RequireConsent ? "1" : "0");
        Append(builder, "skiplogout", client.SkipLogoutConfirmation ? "1" : "0");
        Append(builder, "pkce", client.RequirePkce ? "1" : "0");
        Append(builder, "displayname", client.DisplayName ?? NullSentinel);
        Append(builder, "initiatelogin", client.InitiateLoginUri ?? NullSentinel);
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
        AppendSet(builder, "addidtoken", client.AdditionalIdTokenClaims);
        AppendSet(builder, "adduserinfo", client.AdditionalUserInfoClaims);
        AppendSet(builder, "addaccesstoken", client.AdditionalAccessTokenClaims);
        Append(builder, "atlifetime", client.AccessTokenLifetime?.Ticks.ToString(CultureInfo.InvariantCulture) ?? NullSentinel);
        Append(builder, "idlifetime", client.IdTokenLifetime?.Ticks.ToString(CultureInfo.InvariantCulture) ?? NullSentinel);
        AppendSecrets(builder, client.Secrets);

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())));
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
        // sorting gives the same order under every culture. The count is written too, so a set
        // cannot be confused with a differently-sized one whose members concatenate the same way.
        var ordered = values.OrderBy(v => v, StringComparer.Ordinal).ToList();
        builder.Append(ordered.Count).Append(FieldSeparator);

        foreach (var value in ordered)
            AppendLengthPrefixed(builder, value);
    }

    private static void AppendSecrets(StringBuilder builder, IReadOnlyList<ClientSecret> secrets)
    {
        AppendLengthPrefixed(builder, "secrets");
        builder.Append(secrets.Count).Append(FieldSeparator);

        // Reads the stored hash; never derives one.
        foreach (var secret in secrets)
            AppendLengthPrefixed(builder, secret?.Value ?? NullSentinel);
    }
}
