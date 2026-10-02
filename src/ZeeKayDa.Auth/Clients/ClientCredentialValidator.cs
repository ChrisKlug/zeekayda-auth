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
    /// <summary>
    /// The rules for one secret, in order; the first that finds anything reports it and the rest do
    /// not run. The hasher's own checks come before the empty-secret probe, so a value its hasher
    /// refuses — an excessive work factor included — is never verified.
    /// </summary>
    private static readonly Func<SecretCheck, IReadOnlyList<ZeeKayDaConfigurationFailure>>[] SecretRules =
    [
        HasNoValue,
        IsMalformed,
        HasNoHasher,
        IsRefusedByItsHasher,
        FailsTheEmptySecretProbe,
    ];

    internal static void Validate(
        IClientWithCredentials client,
        CompositeClientSecretHasher hasher,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        foreach (var secret in client.Secrets)
        {
            var check = new SecretCheck(client.ClientId, secret, hasher);
            failures.AddRange(SecretRules.Select(rule => rule(check)).FirstOrDefault(found => found.Count > 0) ?? []);
        }

        if (client.Secrets.Count > CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.credentials.too_many_secrets",
                $"Client '{client.ClientId}' has {client.Secrets.Count} secrets, which exceeds the " +
                $"maximum of {CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient}. " +
                "The two-secret cap exists to support rotation while preserving timing-oracle defences."));
        }
    }

    private sealed record SecretCheck(string ClientId, ClientSecret? Secret, CompositeClientSecretHasher Hasher)
    {
        // Every rule after HasNoValue runs only once it found a value.
        public ClientSecret Stored => Secret!;
    }

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> HasNoValue(SecretCheck check) =>
        string.IsNullOrEmpty(check.Secret?.Value)
            ?
            [
                new(
                    "client.credentials.null_entry",
                    $"Client '{check.ClientId}' has a null entry in Secrets, or one with no Value. It can never be " +
                    "verified; remove it."),
            ]
            : [];

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> IsMalformed(SecretCheck check) =>
        CompositeClientSecretHasher.AlgorithmIdOf(check.Stored.Value) is null
            ?
            [
                new(
                    "client.credentials.malformed_secret",
                    $"Client '{check.ClientId}' has a secret that does not start with $<algorithm id>$, an id of " +
                    "1–32 characters from [a-z0-9-]. A stored secret is a hash such as $pbkdf2-sha256$..., never " +
                    "the plaintext; create one with IClientSecretFactory."),
            ]
            : [];

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> HasNoHasher(SecretCheck check) =>
        check.Hasher.CanVerify(check.Stored)
            ? []
            :
            [
                new(
                    "client.credentials.no_hasher",
                    $"Client '{check.ClientId}' has a secret with algorithm id " +
                    $"'{CompositeClientSecretHasher.AlgorithmIdOf(check.Stored.Value)}', which no registered " +
                    "IClientSecretHasher declares. The secret can never be verified."),
            ];

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> IsRefusedByItsHasher(SecretCheck check) =>
        check.Hasher.ValidateStoredSecret(check.Stored, check.ClientId);

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> FailsTheEmptySecretProbe(SecretCheck check) =>
        check.Hasher.EmptySecretProblem(check.Stored, check.ClientId) is { } problem ? [problem] : [];
}
