using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows.Tests.Fakes;

/// <summary>
/// A controllable <see cref="ISigningKeyRetirementWindowProvider"/> so rotation tests can assert
/// exact retirement-window boundaries without depending on the real 1-hour-floor derivation.
/// </summary>
internal sealed class FakeRetirementWindowProvider(TimeSpan window) : ISigningKeyRetirementWindowProvider
{
    public TimeSpan GetRetirementWindow() => window;
}
