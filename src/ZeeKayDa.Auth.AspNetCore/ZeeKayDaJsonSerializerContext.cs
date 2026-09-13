using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;
using ZeeKayDa.Auth.AspNetCore.Tokens;
using ZeeKayDa.Auth.Discovery;

namespace ZeeKayDa.Auth.AspNetCore;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(OpenIdConfigurationDocument))]
[JsonSerializable(typeof(TokenResponse))]
[JsonSerializable(typeof(TokenErrorResponse))]
[ExcludeFromCodeCoverage(Justification = "Source-generated JSON serialization infrastructure — not hand-written logic.")]
internal sealed partial class ZeeKayDaJsonSerializerContext : JsonSerializerContext { }
