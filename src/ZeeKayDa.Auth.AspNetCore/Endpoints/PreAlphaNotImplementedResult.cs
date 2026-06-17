using Microsoft.AspNetCore.Http;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// Shared 501 result for protocol endpoints advertised by discovery whose real
/// implementations have not landed yet.
/// </summary>
internal static class PreAlphaNotImplementedResult
{
    public static IResult Result { get; } = Results.Problem(
        statusCode: StatusCodes.Status501NotImplemented,
        title: "Endpoint not implemented",
        detail: "This protocol endpoint is advertised for discovery shape stability but is not implemented yet.");
}
