namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Validates a client's shared-secret credentials against the registered hashers and records a
/// <see cref="ZeeKayDaConfigurationFailure"/> for every rule they break.
/// </summary>
internal static class ClientCredentialValidator
{
    /// <summary>
    /// Validates every <see cref="IClientSecret"/> credential the client holds.
    /// </summary>
    internal static void Validate(
        IClientRegistration client,
        CompositeClientSecretHasher hasher,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        ValidateEmptySecretProbe(client, hasher, failures);
        ValidateCredentialConstraints(client, hasher, failures);
        ValidateTwoCredentialCap(client, failures);
    }

    private static void ValidateEmptySecretProbe(
        IClientRegistration client,
        CompositeClientSecretHasher hasher,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        foreach (var _ in client.Credentials
                     .OfType<IClientSecret>()
                     .Where(secret => hasher.Verify(secret, ReadOnlySpan<char>.Empty)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.credentials.empty_secret_accepted",
                $"A credential for client '{client.ClientId}' accepts an empty presented secret. " +
                "Credentials must not accept empty secrets — this would allow unauthenticated access " +
                "to the client. Review the stored credential and the associated hasher."));
        }

        // The empty-secret probe above only catches hashers that accept empty passwords. A
        // credential whose type no registered hasher CanHandle would silently pass validation and
        // only fail at runtime as invalid_client. Reject it here so the misconfiguration is caught
        // at registration time instead.
        foreach (var secret in client.Credentials
                     .OfType<IClientSecret>()
                     .Where(secret => !hasher.CanHandleAny(secret)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.credentials.no_hasher",
                $"Client '{client.ClientId}' has a credential of type '{secret.GetType().Name}' " +
                "for which no registered IClientSecretHasher.CanHandle returns true. " +
                "The credential can never be verified."));
        }
    }

    private static void ValidateCredentialConstraints(
        IClientRegistration client,
        CompositeClientSecretHasher hasher,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        foreach (var secret in client.Credentials.OfType<IClientSecret>())
            failures.AddRange(hasher.GetRegistrationFailures(secret, client.ClientId));
    }

    private static void ValidateTwoCredentialCap(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        var secretCount = client.Credentials.OfType<IClientSecret>().Count();

        if (secretCount > CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.credentials.too_many_secrets",
                $"Client '{client.ClientId}' has {secretCount} IClientSecret credentials, which exceeds the " +
                $"maximum of {CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient}. " +
                "The two-credential cap exists to support credential rotation while preserving timing-oracle defences."));
        }
    }
}
