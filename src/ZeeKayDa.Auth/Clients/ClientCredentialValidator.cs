namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Validates a client's credentials — that each one copies itself, and that its shared secrets suit
/// the registered hashers — and records a <see cref="ZeeKayDaConfigurationFailure"/> for every rule
/// they break.
/// </summary>
internal static class ClientCredentialValidator
{
    /// <summary>
    /// Validates every credential the client holds.
    /// </summary>
    internal static void Validate(
        IClientRegistration client,
        CompositeClientSecretHasher hasher,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        ValidateSnapshots(client, failures);
        ValidateEmptySecretProbe(client, hasher, failures);
        ValidateCredentialConstraints(client, hasher, failures);
        ValidateTwoCredentialCap(client, failures);
    }

    /// <summary>
    /// Every credential, not only a shared secret, must return a new instance from
    /// <see cref="IClientCredential.Snapshot"/>: the resolver serves the copy, and a credential that
    /// hands back itself leaves the store able to change it after this verdict.
    /// </summary>
    /// <remarks>
    /// This is the check for the store's own instance, at startup and at a custom store's write
    /// time. At request time <see cref="ClientRegistrationSnapshot"/> has already applied
    /// <see cref="DescribeCopyProblem"/> to the one <c>Snapshot</c> result it keeps, so a credential
    /// that answers differently when asked again cannot pass here while the copy holds the store's
    /// instance; this rule then runs on credentials that are already copies.
    /// </remarks>
    private static void ValidateSnapshots(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        foreach (var (credential, problem) in client.Credentials
                     .OfType<IClientCredential>()
                     .Select(credential => (credential, DescribeSnapshotProblem(credential)))
                     .Where(entry => entry.Item2 is not null))
        {
            failures.Add(NotCopied(client.ClientId, credential, problem!));
        }
    }

    /// <summary>
    /// What is wrong with <paramref name="copy"/> as the result of <paramref name="credential"/>'s
    /// <see cref="IClientCredential.Snapshot"/>, or <see langword="null"/> when it is a new instance.
    /// </summary>
    internal static string? DescribeCopyProblem(IClientCredential credential, IClientCredential? copy)
    {
        if (copy is null)
            return "returned null";

        return ReferenceEquals(copy, credential) ? "returned the same instance" : null;
    }

    /// <summary>The failure for a credential whose <c>Snapshot</c> did not produce a copy.</summary>
    internal static ZeeKayDaConfigurationFailure NotCopied(
        string clientId,
        IClientCredential credential,
        string problem) =>
        new(
            "client.credentials.not_copied",
            $"Client '{clientId}' has a credential of type '{credential.GetType().Name}' " +
            $"whose Snapshot() {problem}. Snapshot() must return a new instance that shares no " +
            "mutable state with the credential, so the credential that was validated is the one " +
            "the client is authenticated against.");

    private static string? DescribeSnapshotProblem(IClientCredential credential)
    {
        IClientCredential? copy;
        try
        {
            copy = credential.Snapshot();
        }
        catch (Exception ex)
        {
            // Snapshot() is an extension point, and the built-in PBKDF2 copy throws on a null Salt
            // or Hash. A named failure beats an unexplained exception escaping startup validation.
            // Only the type is reported — a ZeeKayDaConfigurationException included, which is
            // deliberately not rethrown with its own text: Snapshot() belongs to a credential, and a
            // message it composes may carry the credential's data into the log.
            return $"threw {ex.GetType().Name}";
        }

        return DescribeCopyProblem(credential, copy);
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
