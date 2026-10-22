namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>Marks every endpoint <c>MapZeeKayDaAuth()</c> maps, and no other.</summary>
internal sealed class FrameworkEndpointMetadata
{
    public static readonly FrameworkEndpointMetadata Instance = new();

    private FrameworkEndpointMetadata()
    {
    }
}
