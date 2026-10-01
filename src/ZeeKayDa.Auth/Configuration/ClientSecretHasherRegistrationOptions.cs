using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Tracks the hasher types registered via <c>AddClientSecretHasher&lt;T&gt;()</c> so that
/// <see cref="ClientSecretHasherOptionsValidator"/> and <c>CompositeClientSecretHasher</c>
/// can determine which hasher is the default at startup.
/// </summary>
internal sealed class ClientSecretHasherRegistrationOptions
{
    internal sealed record HasherRegistration(Type HasherType, bool IsDefault);

    internal List<HasherRegistration> Registrations { get; } = new();

    /// <summary>
    /// The hasher the host marked as default, or PBKDF2 — which every host has — when it marked none.
    /// </summary>
    internal Type DefaultHasherType =>
        Registrations.FirstOrDefault(r => r.IsDefault)?.HasherType ?? typeof(Pbkdf2ClientSecretHasher);
}
