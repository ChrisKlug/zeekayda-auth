using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Tests;

/// <summary>
/// A <see cref="SanitizingLogger{T}"/> over <see cref="NullLogger{T}"/>, for tests that need a
/// logger instance but do not assert on log output.
/// </summary>
internal static class NullSanitizingLogger<T>
{
    public static readonly SanitizingLogger<T> Instance =
        new(NullLogger<T>.Instance, Options.Create(new AuthorizationServerOptions()));
}
