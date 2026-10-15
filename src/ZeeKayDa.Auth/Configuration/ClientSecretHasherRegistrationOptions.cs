using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>The hasher types registered via <c>AddClientSecretHasher&lt;T&gt;()</c>, and which is the default.</summary>
internal sealed class ClientSecretHasherRegistrationOptions
{
    internal sealed record HasherRegistration(Type HasherType, bool IsDefault);

    internal List<HasherRegistration> Registrations { get; } = new();

    /// <summary>The hasher the host marked as default, or PBKDF2 when it marked none.</summary>
    internal Type DefaultHasherType =>
        Registrations.FirstOrDefault(r => r.IsDefault)?.HasherType ?? typeof(Pbkdf2ClientSecretHasher);
}
