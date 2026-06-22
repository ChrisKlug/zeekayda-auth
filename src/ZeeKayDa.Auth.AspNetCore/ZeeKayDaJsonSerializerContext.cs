using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;
using ZeeKayDa.Auth.Discovery;

namespace ZeeKayDa.Auth.AspNetCore;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(OpenIdConfigurationDocument))]
[ExcludeFromCodeCoverage(Justification = "Source-generated JSON serialization infrastructure — not hand-written logic.")]
internal sealed partial class ZeeKayDaJsonSerializerContext : JsonSerializerContext { }
