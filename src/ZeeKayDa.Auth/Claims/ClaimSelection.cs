using System.Text.Json;

namespace ZeeKayDa.Auth.Claims;

/// <summary>Which of a provider's claims land in which destination, all from one pool in one call.</summary>
/// <remarks>
/// Reserved and unwanted names are dropped first. Repeats of a wanted name merge into one JSON array when all
/// strings or all numbers; any other repeat, or a single-valued standard claim repeated, aborts issuance.
/// </remarks>
internal static class ClaimSelection
{
    public static SelectedClaims Select(IReadOnlyList<ClaimRecord> pool, ClaimSelectionPlan plan)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(plan);

        var merged = Merge(pool, plan.All);

        return new SelectedClaims(
            Pick(merged, plan.IdToken),
            Pick(merged, plan.UserInfo),
            Pick(merged, plan.AccessToken));
    }

    /// <summary>
    /// One value per wanted name, in first-seen order. Grouped ignoring case, since a <c>ClaimsPrincipal</c>
    /// reads <c>email_verified</c> and <c>Email_Verified</c> as one claim.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The pool holds a default record, or a wanted claim repeated in a way that cannot be merged.
    /// </exception>
    private static List<KeyValuePair<string, ClaimValue>> Merge(IReadOnlyList<ClaimRecord> pool, IReadOnlySet<string> wanted)
    {
        var grouped = new Dictionary<string, List<ClaimValue>>(StringComparer.OrdinalIgnoreCase);
        var order = new List<string>();

        foreach (var record in pool)
        {
            if (record.IsDefault)
                throw new InvalidOperationException("The claims provider returned a default ClaimRecord, which names no claim.");

            if (ReservedClaimNames.IsReserved(record.Type) || !wanted.Contains(record.Type))
                continue;

            if (!grouped.TryGetValue(record.Type, out var values))
            {
                values = [];
                grouped[record.Type] = values;
                order.Add(record.Type);
            }

            values.Add(record.Value);
        }

        return order.Select(type => KeyValuePair.Create(type, MergeValues(type, grouped[type]))).ToList();
    }

    private static ClaimValue MergeValues(string type, List<ClaimValue> values)
    {
        if (values.Count == 1)
            return values[0];

        if (StandardClaims.IsSingleValued(type))
        {
            throw new InvalidOperationException(
                $"The claims provider returned '{type}' more than once. It is a single-valued standard claim " +
                "(OpenID Connect Core §5.1) and cannot be written as an array.");
        }

        if (!AllOfOneMergeableKind(values))
        {
            throw new InvalidOperationException(
                $"The claims provider returned '{type}' more than once with values that cannot be merged. " +
                "Repeated records merge into one array only when every value is a string, or every value " +
                "is a number; a provider that wants an array of anything else returns ClaimValue.From(array) once.");
        }

        return ClaimValue.ArrayOf(values);
    }

    /// <summary>All strings, or all numbers: the two shapes a JWT consumer turns back into one claim per element.</summary>
    private static bool AllOfOneMergeableKind(List<ClaimValue> values) =>
        values.TrueForAll(value => value.Kind == JsonValueKind.String)
        || values.TrueForAll(value => value.Kind == JsonValueKind.Number);

    private static IReadOnlyDictionary<string, ClaimValue> Pick(
        List<KeyValuePair<string, ClaimValue>> merged,
        IReadOnlySet<string> wanted)
    {
        var selected = new Dictionary<string, ClaimValue>(StringComparer.Ordinal);
        foreach (var (type, value) in merged.Where(claim => wanted.Contains(claim.Key)))
            selected.Add(type, value);

        return selected;
    }
}

/// <summary>The claims each destination carries, one value per name, from one resolution.</summary>
internal sealed record SelectedClaims(
    IReadOnlyDictionary<string, ClaimValue> IdToken,
    IReadOnlyDictionary<string, ClaimValue> UserInfo,
    IReadOnlyDictionary<string, ClaimValue> AccessToken)
{
    public static SelectedClaims None { get; } = new(
        new Dictionary<string, ClaimValue>(StringComparer.Ordinal),
        new Dictionary<string, ClaimValue>(StringComparer.Ordinal),
        new Dictionary<string, ClaimValue>(StringComparer.Ordinal));
}
