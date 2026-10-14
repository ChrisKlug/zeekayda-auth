using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.TestKit.Logging;

/// <summary>
/// Builds a <see cref="SanitizingLogger{T}"/> for tests, so a component that takes one can be
/// constructed outside dependency injection without friend access to the framework.
/// </summary>
/// <example>
/// <code>
/// var reader = new MySigningKeyReader(TestSanitizingLogger.Create(NullLogger&lt;MySigningKeyReader&gt;.Instance));
/// </code>
/// </example>
public static class TestSanitizingLogger
{
    /// <summary>
    /// Creates a <see cref="SanitizingLogger{T}"/> that redacts into <paramref name="inner"/> under
    /// default server options, so exception sanitizing is on exactly as in production.
    /// </summary>
    /// <typeparam name="T">The type whose name is used for the logger category.</typeparam>
    /// <param name="inner">The logger that receives the redacted output.</param>
    /// <returns>A sanitizing logger writing to <paramref name="inner"/>.</returns>
    // Wrapping a raw logger is this method's whole job, as it is for the logger types the rule exempts.
#pragma warning disable ZEEKAYDA0001
    public static SanitizingLogger<T> Create<T>(ILogger<T> inner)
#pragma warning restore ZEEKAYDA0001
    {
        ArgumentNullException.ThrowIfNull(inner);
        return new SanitizingLogger<T>(inner, Options.Create(new AuthorizationServerOptions()));
    }
}
