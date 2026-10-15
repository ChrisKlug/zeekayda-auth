using System.Collections.Immutable;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>One key pair the source listed more than once, as during a renewal, with every source id listing it.</summary>
internal sealed record MergedKey(SigningKey Key, ImmutableArray<SourceKeyId> SourceIds);
