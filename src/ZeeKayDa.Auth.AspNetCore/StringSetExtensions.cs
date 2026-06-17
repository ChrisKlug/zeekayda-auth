namespace ZeeKayDa.Auth.AspNetCore;

internal static class StringSetExtensions
{
    internal static bool ContainsOrdinal(this IReadOnlySet<string> set, string value)
        => set.Contains(value, StringComparer.Ordinal);
}
