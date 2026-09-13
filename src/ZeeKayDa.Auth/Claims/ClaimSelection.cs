using System.Text.Json;

namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// Which of a provider's claims land in which destination. Configuration, not an extension
/// point: the variable part of the subsystem is where claims come from, and that has its seam.
/// </summary>
/// <remarks>
/// <para>
/// Reserved protocol names are dropped from the pool first, so a provider cannot re-assert a
/// subject, an audience or an authentication event, and so is every record no destination
/// wants, since a provider is told that returning more than asked is harmless. Repeated records
/// for one wanted name then merge into one JSON array in the order returned, when every value
/// is a string or every value is a number; any other repeat, or a repeat of a single-valued
/// standard claim, is a provider bug and aborts issuance. Each destination then receives every
/// merged claim its plan wants; a wanted claim the provider did not return is simply absent.
/// </para>
/// <para>
/// Both tokens of one issuance are selected from one pool by one call, so they cannot disagree
/// about a claim.
/// </para>
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
    /// One value per wanted claim name, in first-seen order, with reserved and unwanted names
    /// gone before anything is validated, so only what can reach a token can fail issuance.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The pool holds a default record, or a wanted claim repeated in a way that cannot be merged.
    /// </exception>
    private static List<KeyValuePair<string, ClaimValue>> Merge(IReadOnlyList<ClaimRecord> pool, IReadOnlySet<string> wanted)
    {
        var grouped = new Dictionary<string, List<ClaimValue>>(StringComparer.Ordinal);
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
