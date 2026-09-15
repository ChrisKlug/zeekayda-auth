using Microsoft.AspNetCore.Http;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Records on the request that a terminal interaction outcome committed the response, so the
/// framework can tell its own finished response apart from one the host started for reasons of
/// its own.
/// </summary>
internal static class TerminalResponse
{
    private static readonly object Key = new();

    public static void MarkCommitted(HttpContext context) => context.Items[Key] = true;

    public static bool IsCommitted(HttpContext context) => context.Items.ContainsKey(Key);
}
