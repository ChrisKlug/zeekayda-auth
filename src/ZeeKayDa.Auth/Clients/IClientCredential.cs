namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Marker interface for all credential types that can be stored on a client registration.
/// </summary>
/// <remarks>
/// Use <c>Credentials.OfType&lt;IClientSecret&gt;()</c> to obtain shared-secret credentials.
/// Additional credential subtypes (for example <c>IJwksCredential</c> for
/// <c>private_key_jwt</c>) will be added in future versions.
/// </remarks>
public interface IClientCredential { }
