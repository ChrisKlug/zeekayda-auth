using System.Collections.Frozen;

namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// The standard claims of OpenID Connect Core §5.1, each of which carries one value. A provider
/// returning two records for one of them is a bug: merging <c>email_verified</c> into an array
/// would fail open on a consumer's <c>HasClaim</c>, so issuance aborts instead. Matched ignoring
/// case, as that consumer matches.
/// </summary>
internal static class StandardClaims
{
    private static readonly FrozenSet<string> SingleValued = FrozenSet.ToFrozenSet(
        [
            "sub", "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username",
            "profile", "picture", "website", "email", "email_verified", "gender", "birthdate",
            "zoneinfo", "locale", "phone_number", "phone_number_verified", "address", "updated_at",
        ],
        StringComparer.OrdinalIgnoreCase);

    public static bool IsSingleValued(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        return SingleValued.Contains(name);
    }
}
