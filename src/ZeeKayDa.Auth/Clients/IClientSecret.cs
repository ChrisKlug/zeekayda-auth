namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Marker interface for shared-secret credentials stored on a client registration.
/// </summary>
/// <remarks>
/// <para>
/// This interface carries no behaviour — credential verification is delegated to
/// <c>IClientSecretHasher</c> implementations so fixed-time comparison is centrally
/// guaranteed and custom algorithms can be added without framework changes.
/// </para>
/// <para>
/// During a credential rotation window, a client may hold at most two active
/// <see cref="IClientSecret"/> entries simultaneously. Authenticators MUST attempt
/// verification against ALL matching credentials before returning a failure result.
/// </para>
/// </remarks>
public interface IClientSecret : IClientCredential { }
