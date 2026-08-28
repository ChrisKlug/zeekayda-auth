namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// Searches an exception chain for an exception of a given type. Host-startup tests need this
/// because the framework wraps configuration failures in several layers before they surface.
/// </summary>
internal static class ExceptionChain
{
    /// <summary>
    /// Returns the first exception of type <typeparamref name="T"/> found in
    /// <paramref name="exception"/> or anywhere beneath it, or <see langword="null"/> if there is
    /// none.
    /// </summary>
    /// <remarks>
    /// The walk is depth-first and covers both branches of the chain:
    /// <list type="bullet">
    /// <item><description>
    /// an <see cref="AggregateException"/> is searched through every one of its
    /// <see cref="AggregateException.InnerExceptions"/>, each recursively;
    /// </description></item>
    /// <item><description>
    /// if that finds nothing — including for an <see cref="AggregateException"/> — the walk
    /// continues into <see cref="Exception.InnerException"/> rather than stopping. A match nested
    /// below an aggregate that holds no match is therefore still found.
    /// </description></item>
    /// </list>
    /// </remarks>
    public static T? FindInChain<T>(Exception? exception) where T : Exception
    {
        while (exception is not null)
        {
            if (exception is T match)
                return match;

            if (exception is AggregateException aggregate &&
                aggregate.InnerExceptions.Select(FindInChain<T>).FirstOrDefault(m => m is not null) is { } found)
            {
                return found;
            }

            exception = exception.InnerException;
        }

        return null;
    }
}
