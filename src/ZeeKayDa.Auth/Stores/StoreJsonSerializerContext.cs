using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace ZeeKayDa.Auth.Stores;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    PropertyNameCaseInsensitive = true,
    NumberHandling = JsonNumberHandling.AllowReadingFromString)]
[JsonSerializable(typeof(AuthorizationCodeEntry))]
[JsonSerializable(typeof(RefreshTokenEntry))]
[JsonSerializable(typeof(AuthorizationCodeTombstoneEnvelope))]
[JsonSerializable(typeof(RefreshTokenGrantRecord))]
[JsonSerializable(typeof(RefreshTokenGrantIndexEnvelope))]
[ExcludeFromCodeCoverage(Justification = "Source-generated JSON serialization infrastructure — not hand-written logic.")]
internal sealed partial class StoreJsonSerializerContext : JsonSerializerContext { }
