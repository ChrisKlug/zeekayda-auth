using Microsoft.AspNetCore.Http;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Marks a response a terminal interaction outcome committed, as opposed to one the host started.
/// </summary>
internal static class TerminalResponse
{
    private static readonly object Key = new();

    public static void MarkCommitted(HttpContext context) => context.Items[Key] = true;

    public static bool IsCommitted(HttpContext context) => context.Items.ContainsKey(Key);
}
