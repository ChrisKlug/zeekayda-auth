using System.Text.Json.Serialization;
using ZeeKayDa.Auth.Discovery;

namespace ZeeKayDa.Auth.AspNetCore;

[JsonSerializable(typeof(OpenIdConfigurationDocument))]
internal sealed partial class ZeeKayDaJsonSerializerContext : JsonSerializerContext { }
