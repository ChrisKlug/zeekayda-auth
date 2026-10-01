namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// A builder for configuring a ZeeKayDa.Auth server hosted in ASP.NET Core.
/// </summary>
/// <remarks>
/// Returned by <c>AddZeeKayDaAuth(configure)</c>. Everything that configures
/// <see cref="ZeeKayDaAuthCoreBuilder"/> works here too and keeps returning this type; the
/// extensions that need the HTTP surface, such as <c>WithProviders</c>, exist only here.
/// </remarks>
public sealed class ZeeKayDaAuthBuilder : ZeeKayDaAuthCoreBuilder
{
    internal ZeeKayDaAuthBuilder(ZeeKayDaAuthCoreBuilder core)
        : base(core.Services)
    {
    }
}
