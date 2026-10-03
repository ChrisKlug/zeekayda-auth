namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Validates a client's credentials — that each secret is readable and suits a registered hasher —
/// and records a <see cref="ZeeKayDaConfigurationFailure"/> for every rule they break.
/// </summary>
/// <remarks>
/// One bad secret refuses the whole client, even when its other secret is fine: skipping it would
/// hide a broken rotation until the good secret is retired. No message the framework writes contains a
/// stored value, beyond the well-formed algorithm id <c>client.credentials.no_hasher</c> names. A
/// hasher's own <c>ValidateStoredSecret</c> messages pass through as it wrote them.
/// </remarks>
internal static class ClientCredentialValidator
{
    /// <summary>
    /// The rules for one secret, in order; the first that finds anything reports it and the rest do
    /// not run.
    /// </summary>
    private static readonly Func<SecretCheck, IReadOnlyList<ZeeKayDaConfigurationFailure>>[] SecretRules =
    [
        HasNoValue,
        IsMalformed,
        HasNoHasher,
        IsRefusedByItsHasher,
    ];

    internal static void Validate(
        IClientWithCredentials client,
        ClientSecretHasherRegistry registry,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        // Counted by enumerating, never from Count: a store's own list can report fewer entries than
        // it yields, and the cap bounds the timing work of every failed authentication.
        var count = 0;
        foreach (var secret in client.Secrets)
        {
            count++;
            var check = new SecretCheck(client.ClientId, secret, registry);
            failures.AddRange(SecretRules.Select(rule => rule(check)).FirstOrDefault(found => found.Count > 0) ?? []);
        }

        if (count > ClientSecrets.MaxActiveSecretsPerClient)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.credentials.too_many_secrets",
                $"Client '{client.ClientId}' has {count} secrets, which exceeds the " +
                $"maximum of {ClientSecrets.MaxActiveSecretsPerClient}. " +
                "The two-secret cap exists to support rotation while preserving timing-oracle defences."));
        }
    }

    private sealed record SecretCheck(string ClientId, ClientSecret? Secret, ClientSecretHasherRegistry Registry)
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
        ClientSecretHasherRegistry.AlgorithmIdOf(check.Stored.Value) is null
            ?
            [
                new(
                    "client.credentials.malformed_secret",
                    $"Client '{check.ClientId}' has a secret that does not start with $<algorithm id>$, an id of " +
                    "1–32 characters from [a-z0-9-]. A stored secret is a hash such as $pbkdf2-sha256$..., never " +
                    "the plaintext; create one with IClientSecrets."),
            ]
            : [];

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> HasNoHasher(SecretCheck check) =>
        check.Registry.CanVerify(check.Stored)
            ? []
            :
            [
                new(
                    "client.credentials.no_hasher",
                    $"Client '{check.ClientId}' has a secret with algorithm id " +
                    $"'{ClientSecretHasherRegistry.AlgorithmIdOf(check.Stored.Value)}', which no registered " +
                    "IClientSecretHasher declares. The secret can never be verified."),
            ];

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> IsRefusedByItsHasher(SecretCheck check) =>
        check.Registry.ValidateStoredSecret(check.Stored, check.ClientId);
}
