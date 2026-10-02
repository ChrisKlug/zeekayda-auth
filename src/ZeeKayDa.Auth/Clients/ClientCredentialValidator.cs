namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Validates a client's credentials — that each secret is readable and suits a registered hasher —
/// and records a <see cref="ZeeKayDaConfigurationFailure"/> for every rule they break.
/// </summary>
/// <remarks>
/// One bad secret refuses the whole client, even when its other secret is fine: skipping it would
/// hide a broken rotation until the good secret is retired. No message contains a stored value; the
/// one exception is the algorithm id, which <c>client.credentials.no_hasher</c> names.
/// </remarks>
internal static class ClientCredentialValidator
{
    internal static void Validate(
        IClientWithCredentials client,
        CompositeClientSecretHasher hasher,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        foreach (var secret in client.Secrets)
            ValidateSecret(client.ClientId, secret, hasher, failures);

        if (client.Secrets.Count > CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.credentials.too_many_secrets",
                $"Client '{client.ClientId}' has {client.Secrets.Count} secrets, which exceeds the " +
                $"maximum of {CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient}. " +
                "The two-secret cap exists to support rotation while preserving timing-oracle defences."));
        }
    }

    private static void ValidateSecret(
        string clientId,
        ClientSecret? secret,
        CompositeClientSecretHasher hasher,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        if (string.IsNullOrEmpty(secret?.Value))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.credentials.null_entry",
                $"Client '{clientId}' has a null entry in Secrets, or one with no Value. It can never be " +
                "verified; remove it."));
            return;
        }

        if (CompositeClientSecretHasher.AlgorithmIdOf(secret.Value) is not { } algorithmId)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.credentials.malformed_secret",
                $"Client '{clientId}' has a secret that does not start with $<algorithm id>$. A stored " +
                "secret is a hash such as $pbkdf2-sha256$..., never the plaintext; create one with " +
                "IClientSecretFactory."));
            return;
        }

        if (!hasher.CanVerify(secret))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.credentials.no_hasher",
                $"Client '{clientId}' has a secret with algorithm id '{algorithmId}', which no registered " +
                "IClientSecretHasher declares. The secret can never be verified."));
            return;
        }

        if (hasher.AcceptsEmptySecret(secret))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.credentials.empty_secret_accepted",
                $"A secret for client '{clientId}' accepts an empty presented secret. " +
                "Secrets must not accept empty input — this would allow unauthenticated access " +
                "to the client. Review the stored secret and the associated hasher."));
        }

        failures.AddRange(hasher.ValidateStoredSecret(secret, clientId));
    }
}
