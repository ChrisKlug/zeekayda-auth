using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tests;

/// <summary>An <see cref="IOptionsMonitor{TOptions}"/> that always returns one value.</summary>
internal sealed class FixedOptionsMonitor<T>(T value) : IOptionsMonitor<T>
{
    public T CurrentValue => value;
    public T Get(string? name) => value;
    public IDisposable? OnChange(Action<T, string?> listener) => null;
}
