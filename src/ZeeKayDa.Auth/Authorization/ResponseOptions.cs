using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// Response configuration options.
/// </summary>
public sealed class ResponseOptions
{
    private ICollection<ResponseType> _typesSupported = [ResponseType.Code];
    private ICollection<ResponseMode> _modesSupported = [ResponseMode.Query];
    private bool _frozen;

    /// <summary>
    /// Gets or sets the response types supported by this authorization server.
    /// Defaults to <c>[<see cref="ResponseType.Code"/>]</c>.
    /// </summary>
    /// <remarks>
    /// Maps to the <c>response_types_supported</c> discovery metadata field.
    /// </remarks>
    public ICollection<ResponseType> TypesSupported
    {
        get => _typesSupported;
        set => _typesSupported = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.Response.TypesSupported");
    }

    /// <summary>
    /// Gets or sets the response modes supported by this authorization server.
    /// Defaults to <c>[<see cref="ResponseMode.Query"/>]</c>.
    /// </summary>
    /// <remarks>
    /// Maps to the <c>response_modes_supported</c> discovery metadata field.
    /// </remarks>
    public ICollection<ResponseMode> ModesSupported
    {
        get => _modesSupported;
        set => _modesSupported = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.Response.ModesSupported");
    }

    /// <summary>Makes every collection read-only and refuses any later replacement.</summary>
    internal void Freeze()
    {
        if (_frozen)
            return;

        TypesSupported = FrozenOptions.Copy(TypesSupported);
        ModesSupported = FrozenOptions.Copy(ModesSupported);
        _frozen = true;
    }
}
