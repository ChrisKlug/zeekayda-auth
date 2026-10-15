using System.Reflection;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Tests.Logging;

/// <summary>
/// Pins what makes the sanitizing logger impossible to substitute: it is public, so a provider
/// package referencing only core ZeeKayDa.Auth can inject it, but nothing outside the framework can
/// construct it or derive from it.
/// </summary>
public sealed class SanitizingLoggerVisibilityTests
{
    [Fact]
    public void SanitizingLogger_is_public()
    {
        typeof(SanitizingLogger<>).IsPublic.Should().BeTrue();
    }

    [Fact]
    public void SanitizingLogger_has_no_constructor_another_assembly_can_call_or_chain_to()
    {
        // A public or protected constructor would let a host construct one around a logger of its
        // choosing, or derive one that overrides nothing but skips redaction by never calling it.
        typeof(SanitizingLogger<>)
            .GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .Should().OnlyContain(constructor => constructor.IsAssembly);
    }

    [Fact]
    public void SanitizingLogger_members_cannot_be_overridden()
    {
        typeof(SanitizingLogger<>)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
            .Should().OnlyContain(method => !method.IsVirtual || method.IsFinal);
    }

    [Fact]
    public void The_registered_subclass_remains_internal_and_sealed()
    {
        var type = typeof(RegisteredSanitizingLogger<>);
        type.IsVisible.Should().BeFalse();
        type.IsSealed.Should().BeTrue();
    }
}
