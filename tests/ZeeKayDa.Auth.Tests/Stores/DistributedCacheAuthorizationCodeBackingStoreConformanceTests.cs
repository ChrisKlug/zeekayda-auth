using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Stores;
using ZeeKayDa.Auth.TestKit.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Runs the ADR 0013 §10 conformance kit against
/// <see cref="DistributedCacheAuthorizationCodeBackingStore"/>. The atomicity assertion is
/// skipped: this store composes a non-atomic read-then-write over <see cref="IDistributedCache"/>
/// and is documented dev/test-only, not for production (see its type-level remarks).
/// </summary>
public sealed class DistributedCacheAuthorizationCodeBackingStoreConformanceTests : AuthorizationCodeBackingStoreConformanceTests
{
    protected override bool SupportsAtomicInsert => false;

    protected override IAuthorizationCodeBackingStore CreateStore()
        => new DistributedCacheAuthorizationCodeBackingStore(
            new MemoryDistributedCache(new OptionsWrapper<MemoryDistributedCacheOptions>(new MemoryDistributedCacheOptions())),
            TimeProvider.System);

    protected override IAuthorizationCodeBackingStore CreateFaultInjectedStore(Exception fault)
        => new DistributedCacheAuthorizationCodeBackingStore(new AlwaysFaultingDistributedCache(fault), TimeProvider.System);

    /// <summary>An <see cref="IDistributedCache"/> whose async operations always throw the supplied
    /// fault, used to prove the backing store propagates rather than swallows transport faults.</summary>
    private sealed class AlwaysFaultingDistributedCache(Exception fault) : IDistributedCache
    {
        public byte[]? Get(string key) => throw fault;
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => throw fault;
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => throw fault;
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default) => throw fault;
        public void Refresh(string key) => throw fault;
        public Task RefreshAsync(string key, CancellationToken token = default) => throw fault;
        public void Remove(string key) => throw fault;
        public Task RemoveAsync(string key, CancellationToken token = default) => throw fault;
    }
}
