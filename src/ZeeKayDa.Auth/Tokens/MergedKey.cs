using System.Collections.Immutable;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// One key the source listed more than once, as a certificate renewed over its own key pair is listed
/// beside the certificate it renews, with every <see cref="SourceIds">source id</see> listing it, in ordinal order.
/// </summary>
internal sealed record MergedKey(SigningKey Key, ImmutableArray<SourceKeyId> SourceIds);
