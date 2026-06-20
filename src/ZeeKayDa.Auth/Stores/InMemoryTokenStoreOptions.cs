namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Configuration options for the in-memory token stores.
/// </summary>
/// <remarks>
/// These options are specific to the in-memory store implementations and are kept separate
/// from <see cref="ZeeKayDa.Auth.AuthorizationServerOptions"/> per the ADR 0002 grouping rule —
/// consumers who replace the default store should not be required to configure options that
/// only apply to the default.
/// </remarks>
public sealed class InMemoryTokenStoreOptions
{
    /// <summary>
    /// Gets or sets how long a per-handle <see cref="System.Threading.SemaphoreSlim"/> is
    /// retained after its associated cache entry has expired. Defaults to 5 minutes.
    /// </summary>
    /// <remarks>
    /// Semaphores are evicted lazily — on the next operation that touches a key whose entry
    /// has already expired beyond this window. A longer window reduces the risk of premature
    /// semaphore recycling at the cost of a small memory overhead in high-throughput scenarios.
    /// </remarks>
    public TimeSpan SemaphoreEvictionWindow { get; set; } = TimeSpan.FromMinutes(5);
}
