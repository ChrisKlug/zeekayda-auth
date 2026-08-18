using System;
using Microsoft.CodeAnalysis;

namespace ZeeKayDa.Auth.Analyzers;

/// <summary>
/// Determines whether a compilation is one of ZeeKayDa.Auth's own assemblies, for analyzers that
/// only apply to the framework's own code (not to consumers of the framework).
/// </summary>
internal static class ZeeKayDaAssemblyGate
{
    /// <summary>
    /// Returns true when <paramref name="compilation"/> belongs to <c>ZeeKayDa.Auth</c> or one of
    /// its sub-assemblies, excluding <c>ZeeKayDa.Auth.Analyzers</c> itself.
    /// </summary>
    /// <remarks>
    /// Checks the assembly name rather than any declared C# namespace: extension-method classes
    /// commonly declare themselves in a framework namespace such as
    /// <c>Microsoft.Extensions.DependencyInjection</c> for discoverability, which would otherwise
    /// let ZeeKayDa.Auth's own code escape analysis by declared-namespace text alone.
    /// </remarks>
    public static bool IsZeeKayDaAssembly(Compilation compilation)
    {
        var assemblyName = compilation.AssemblyName;
        if (assemblyName is null) return false;

        if (assemblyName == "ZeeKayDa.Auth.Analyzers" ||
            assemblyName.StartsWith("ZeeKayDa.Auth.Analyzers.", StringComparison.Ordinal))
            return false;

        return assemblyName == "ZeeKayDa.Auth"
            || assemblyName.StartsWith("ZeeKayDa.Auth.", StringComparison.Ordinal);
    }
}
