namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// The fail-closed wrapper around backend calls: any fault becomes a <see cref="ZeeKayDaStoreException"/>,
/// but cancellation is rethrown, since it is not a store fault.
/// </summary>
internal static class StoreGuard
{
    /// <summary>Runs <paramref name="operation"/>, converting native faults to <see cref="ZeeKayDaStoreException"/>.</summary>
    /// <param name="operation">The backend call to run.</param>
    /// <param name="action">A short description of the action, used in the wrapped exception's message.</param>
    public static async Task<T> Guarded<T>(Func<Task<T>> operation, string action)
    {
        try
        {
            return await operation().ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is not ZeeKayDaStoreException)
        {
            throw new ZeeKayDaStoreException($"Failed to {action}.", ex);
        }
    }

    /// <summary>Runs <paramref name="operation"/>, converting native faults to <see cref="ZeeKayDaStoreException"/>.</summary>
    /// <param name="operation">The backend call to run.</param>
    /// <param name="action">A short description of the action, used in the wrapped exception's message.</param>
    public static async Task Guarded(Func<Task> operation, string action)
    {
        try
        {
            await operation().ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is not ZeeKayDaStoreException)
        {
            throw new ZeeKayDaStoreException($"Failed to {action}.", ex);
        }
    }
}
