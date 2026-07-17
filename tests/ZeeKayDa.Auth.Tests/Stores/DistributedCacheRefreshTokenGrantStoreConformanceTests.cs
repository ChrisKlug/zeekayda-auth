using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Stores;
using ZeeKayDa.Auth.TestKit.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Runs the ADR 0014 §9 conformance kit against <see cref="DistributedCacheRefreshTokenGrantStore"/>.
/// The mid-revoke-insert completeness case is relaxed: this store maintains its own
/// non-transactional secondary indexes over <see cref="IDistributedCache"/> and is documented
/// dev/test-only, not for production (ADR 0014 §8's explicit caveat — see the store's type-level
/// remarks). Its CAS invariant is a read-then-write, also not atomic, so that case is skipped too.
/// </summary>
public sealed class DistributedCacheRefreshTokenGrantStoreConformanceTests : RefreshTokenGrantStoreConformanceTests
{
    protected override bool SupportsAtomicConsume => false;

    protected override bool SupportsMidRevokeInsertCompleteness => false;

    protected override IRefreshTokenGrantStore CreateStore()
        => new DistributedCacheRefreshTokenGrantStore(
            new MemoryDistributedCache(new OptionsWrapper<MemoryDistributedCacheOptions>(new MemoryDistributedCacheOptions())));

    protected override IRefreshTokenGrantStore CreateFaultInjectedStore(Exception fault)
        => new DistributedCacheRefreshTokenGrantStore(new AlwaysFaultingDistributedCache(fault));

    /// <summary>An <see cref="IDistributedCache"/> whose async operations always throw the supplied
    /// fault, used to prove the grant store propagates rather than swallows transport faults.</summary>
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
