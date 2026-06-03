namespace ZeeKayDa.Auth;

/// <summary>
/// Response configuration options.
/// </summary>
public sealed class ResponseOptions
{
    /// <summary>
    /// Gets or sets the response types supported by this authorization server.
    /// Defaults to <c>[<see cref="ResponseType.Code"/>]</c>.
    /// </summary>
    /// <remarks>
    /// Maps to the <c>response_types_supported</c> discovery metadata field.
    /// </remarks>
    public ICollection<ResponseType> TypesSupported { get; set; } = [ResponseType.Code];

    /// <summary>
    /// Gets or sets the response modes supported by this authorization server.
    /// Defaults to <c>[<see cref="ResponseMode.Query"/>]</c>.
    /// </summary>
    /// <remarks>
    /// Maps to the <c>response_modes_supported</c> discovery metadata field.
    /// </remarks>
    public ICollection<ResponseMode> ModesSupported { get; set; } = [ResponseMode.Query];
}
