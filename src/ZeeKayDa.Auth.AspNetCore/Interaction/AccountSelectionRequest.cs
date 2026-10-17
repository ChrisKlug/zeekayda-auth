namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// What the host's account picker offers, read through <see cref="AccountSelectionInteraction.GetRequestAsync"/>.
/// </summary>
public sealed class AccountSelectionRequest
{
    internal AccountSelectionRequest(ClientInformation client, IReadOnlyList<SignedInAccount> accounts)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(accounts);

        Client = client;
        Accounts = accounts;
    }

    /// <summary>The client the user is choosing an account for.</summary>
    public ClientInformation Client { get; }

    /// <summary>
    /// The accounts the user may continue as without signing in again, the most recently used
    /// first; each one's <see cref="SignedInAccount.Subject"/> goes back to
    /// <see cref="AccountSelectionInteraction.SelectAsync"/>. Accounts the request rules out — another
    /// user than its <c>id_token_hint</c> names, or one that authenticated longer ago than its
    /// <c>max_age</c> — are left out. Empty when every account has been signed out since the browser
    /// was sent here: offer <see cref="AccountSelectionInteraction.UseAnotherAccountAsync"/> alone.
    /// </summary>
    public IReadOnlyList<SignedInAccount> Accounts { get; }
}
