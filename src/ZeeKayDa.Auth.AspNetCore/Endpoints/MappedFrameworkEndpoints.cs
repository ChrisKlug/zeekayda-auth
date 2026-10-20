using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// The route groups <c>MapZeeKayDaAuth()</c> mapped, read at startup once the host has added its
/// own conventions to them.
/// </summary>
internal sealed class MappedFrameworkEndpoints
{
    private readonly List<EndpointDataSource> _groups = [];

    /// <summary>Every framework endpoint as routing will build it, the host's conventions included.</summary>
    public IEnumerable<Endpoint> Endpoints => _groups.SelectMany(group => group.Endpoints);

    public void Add(EndpointDataSource group) => _groups.Add(group);
}
