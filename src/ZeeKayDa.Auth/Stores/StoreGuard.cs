namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Shared fail-closed wrapper for coordinator-to-backend calls. Maps any thrown
/// exception into <see cref="ZeeKayDaStoreException"/>, while rethrowing
/// <see cref="OperationCanceledException"/> unwrapped because cancellation is not a store fault.
/// </summary>
/// <remarks>
/// Shared between <c>AuthorizationCodeStore</c> and <c>RefreshTokenStore</c> so the two sealed
/// coordinators do not duplicate this logic.
/// </remarks>
internal static class StoreGuard
{
    /// <summary>Runs <paramref name="operation"/>, converting native faults to <see cref="ZeeKayDaStoreException"/>.</summary>
    /// <param name="operation">The backend call to run.</param>
    /// <param name="action">A short description of the action, used in the wrapped exception's message.</param>
    public static async ValueTask<T> Guarded<T>(Func<ValueTask<T>> operation, string action)
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
    public static async ValueTask Guarded(Func<ValueTask> operation, string action)
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
