using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace ZeeKayDa.Auth.Stores;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(AuthorizationCodeEntry))]
[JsonSerializable(typeof(RefreshTokenEntry))]
[JsonSerializable(typeof(AuthorizationCodeTombstone))]
[JsonSerializable(typeof(RefreshTokenCachePayload))]
[ExcludeFromCodeCoverage(Justification = "Source-generated JSON serialization infrastructure — not hand-written logic.")]
internal sealed partial class StoreJsonSerializerContext : JsonSerializerContext { }
