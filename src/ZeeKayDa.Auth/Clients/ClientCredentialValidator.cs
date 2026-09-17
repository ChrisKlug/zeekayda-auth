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
    /// <remarks>
    /// The secret rules run on the credentials the client will be authenticated against. For a
    /// store's own registration — at startup and at a custom store's write time — that is each
    /// credential's <see cref="IClientCredential.Snapshot"/>, the copy the resolver will later serve;
    /// checking the store's instance instead would let a copy that differs from it pass here and
    /// fail every lookup. For the resolver's <see cref="ClientRegistrationSnapshot"/> it is the
    /// credentials the snapshot already holds, checked as they are: copying them again would
    /// validate a second copy while the client is authenticated against the first, and a
    /// <c>Snapshot</c> whose successive copies differ would get an unsafe first copy served.
    /// </remarks>
    internal static void Validate(
        IClientRegistration client,
        CompositeClientSecretHasher hasher,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        // The snapshot has already refused null entries and anything that is not a usable copy.
        var secrets = client is ClientRegistrationSnapshot
            ? client.Credentials.OfType<IClientSecret>().ToList()
            : CopySecrets(client, failures);

        ValidateEmptySecretProbe(client.ClientId, secrets, hasher, failures);
        ValidateCredentialConstraints(client.ClientId, secrets, hasher, failures);
        ValidateTwoCredentialCap(client.ClientId, secrets, failures);
    }

    /// <summary>
    /// Copies every credential, not only a shared secret, and returns the copies that are secrets.
    /// Every credential must return a new instance from <see cref="IClientCredential.Snapshot"/>:
    /// the resolver serves the copy, and a credential that hands back itself leaves the store able
    /// to change it after this verdict.
    /// </summary>
    /// <remarks>
    /// Never called for the resolver's <see cref="ClientRegistrationSnapshot"/>, which applied
    /// <see cref="DescribeCopyProblem"/> to the one <c>Snapshot</c> result it keeps: a credential
    /// asked a second time could answer differently from what is served.
    /// </remarks>
    private static List<IClientSecret> CopySecrets(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        // Filtering by type skips a null entry silently; the registration would then pass here and
        // fail every lookup.
        if (client.Credentials.Any(credential => credential is null))
            failures.Add(NullCredential(client.ClientId));

        var secrets = new List<IClientSecret>();
        foreach (var (copy, failure) in client.Credentials
                     .OfType<IClientCredential>()
                     .Select(credential => Copy(client.ClientId, credential)))
        {
            if (failure is not null)
                failures.Add(failure);
            else if (copy is IClientSecret secret)
                secrets.Add(secret);
        }

        return secrets;
    }

    private static (IClientCredential? Copy, ZeeKayDaConfigurationFailure? Failure) Copy(
        string clientId,
        IClientCredential credential)
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
            return (null, NotCopied(clientId, credential, $"threw {ex.GetType().Name}"));
        }

        return DescribeCopyProblem(credential, copy) is { } problem
            ? (null, NotCopied(clientId, credential, problem))
            : (copy, null);
    }

    /// <summary>
    /// What is wrong with <paramref name="copy"/> as the result of <paramref name="credential"/>'s
    /// <see cref="IClientCredential.Snapshot"/>, or <see langword="null"/> when it is a usable copy.
    /// </summary>
    internal static string? DescribeCopyProblem(IClientCredential credential, IClientCredential? copy)
    {
        if (copy is null)
            return "returned null";

        if (ReferenceEquals(copy, credential))
            return "returned the same instance";

        // A secret whose copy is not a secret would drop out of every secret rule, and the client
        // would fail every authentication as if it had presented the wrong secret.
        return credential is IClientSecret && copy is not IClientSecret
            ? $"returned a {copy.GetType().Name}, which is not an IClientSecret"
            : null;
    }

    /// <summary>The failure for a <see langword="null"/> entry in a registration's credentials.</summary>
    internal static ZeeKayDaConfigurationFailure NullCredential(string clientId) =>
        new(
            "client.credentials.null_entry",
            $"Client '{clientId}' has a null entry in Credentials. A null credential can never be " +
            "copied or verified; remove it.");

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

    private static void ValidateEmptySecretProbe(
        string clientId,
        List<IClientSecret> secrets,
        CompositeClientSecretHasher hasher,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        foreach (var _ in secrets.Where(secret => hasher.Verify(secret, ReadOnlySpan<char>.Empty)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.credentials.empty_secret_accepted",
                $"A credential for client '{clientId}' accepts an empty presented secret. " +
                "Credentials must not accept empty secrets — this would allow unauthenticated access " +
                "to the client. Review the stored credential and the associated hasher."));
        }

        // The empty-secret probe above only catches hashers that accept empty passwords. A
        // credential whose type no registered hasher CanHandle would silently pass validation and
        // only fail at runtime as invalid_client. Reject it here so the misconfiguration is caught
        // at registration time instead.
        foreach (var secret in secrets.Where(secret => !hasher.CanHandleAny(secret)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.credentials.no_hasher",
                $"Client '{clientId}' has a credential of type '{secret.GetType().Name}' " +
                "for which no registered IClientSecretHasher.CanHandle returns true. " +
                "The credential can never be verified."));
        }
    }

    private static void ValidateCredentialConstraints(
        string clientId,
        List<IClientSecret> secrets,
        CompositeClientSecretHasher hasher,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        foreach (var secret in secrets)
            failures.AddRange(hasher.GetRegistrationFailures(secret, clientId));
    }

    private static void ValidateTwoCredentialCap(
        string clientId,
        List<IClientSecret> secrets,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        if (secrets.Count > CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.credentials.too_many_secrets",
                $"Client '{clientId}' has {secrets.Count} IClientSecret credentials, which exceeds the " +
                $"maximum of {CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient}. " +
                "The two-credential cap exists to support credential rotation while preserving timing-oracle defences."));
        }
    }
}
