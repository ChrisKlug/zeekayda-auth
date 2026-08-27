using Azure;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;

/// <summary>
/// An <see cref="AsyncPageable{T}"/> over an in-memory item source, one item per page, so tests
/// can hand the fake SDK clients a listing that yields items and then optionally throws — the
/// shape the readers' per-<c>MoveNextAsync</c> fault mapping is written against.
/// </summary>
internal sealed class FakeAsyncPageable<T>(IEnumerable<Func<T>> items) : AsyncPageable<T>
    where T : notnull
{
    /// <summary>A pageable that yields <paramref name="items"/> and completes.</summary>
    public static FakeAsyncPageable<T> Of(params T[] items) =>
        new(items.Select(item => (Func<T>)(() => item)));

    /// <summary>A pageable whose first <c>MoveNextAsync</c> throws <paramref name="exception"/>.</summary>
    public static FakeAsyncPageable<T> Throwing(Exception exception) =>
        new([() => throw exception]);

    public override async IAsyncEnumerable<Page<T>> AsPages(
        string? continuationToken = null, int? pageSizeHint = null)
    {
        foreach (var item in items)
        {
            await Task.Yield();
            yield return Page<T>.FromValues([item()], null, new FakeAzureResponse(200));
        }
    }
}
