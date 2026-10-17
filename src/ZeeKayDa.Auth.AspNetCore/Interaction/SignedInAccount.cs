namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>An account the browser is signed in to, as a host page sees it.</summary>
public sealed class SignedInAccount
{
    internal SignedInAccount(string subject, string loginIdentifier)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);
        ArgumentException.ThrowIfNullOrEmpty(loginIdentifier);

        Subject = subject;
        LoginIdentifier = loginIdentifier;
    }

    /// <summary>
    /// The account's subject: the one the host's sign-in supplied, or, for a user who signed in
    /// through an external provider, the subject <see cref="ExternalSubject.Derive"/> computes.
    /// </summary>
    public string Subject { get; }

    /// <summary>
    /// What to show the user for this account: the login identifier its sign-in gave, or
    /// <see cref="Subject"/> when it gave none. Encode it when rendering.
    /// </summary>
    public string LoginIdentifier { get; }

    internal static SignedInAccount Of(SsoSessionState account) => new(account.Subject, account.LoginIdentifier ?? account.Subject);
}
