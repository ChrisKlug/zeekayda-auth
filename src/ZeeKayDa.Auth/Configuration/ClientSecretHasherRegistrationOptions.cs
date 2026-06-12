namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Tracks the hasher types registered via <c>AddSecretsHasher&lt;T&gt;()</c> so that
/// <see cref="ClientSecretHasherOptionsValidator"/> and <c>CompositeClientSecretHasher</c>
/// can determine which hasher is the default at startup.
/// </summary>
internal sealed class ClientSecretHasherRegistrationOptions
{
    internal sealed record HasherRegistration(Type HasherType, bool IsDefault);

    internal List<HasherRegistration> Registrations { get; } = new();
}
