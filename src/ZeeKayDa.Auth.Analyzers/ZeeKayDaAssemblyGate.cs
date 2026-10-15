using System;
using Microsoft.CodeAnalysis;

namespace ZeeKayDa.Auth.Analyzers;

/// <summary>Whether a compilation is one of ZeeKayDa.Auth's own assemblies, not a consumer's.</summary>
internal static class ZeeKayDaAssemblyGate
{
    // By assembly name, not namespace: our extension classes declare framework namespaces such as Microsoft.Extensions.DependencyInjection.
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
