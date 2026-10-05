namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// A refusal the client is answered with as <c>access_denied</c> (RFC 6749 §4.1.2.1): the
/// framework's <c>error_description</c>, which names the stage, and the <c>zkd_error</c> sub-code a
/// client registered with <c>EnableZkdErrorCodes</c> also receives.
/// </summary>
/// <remarks>
/// <para>
/// A closed set of framework constants. Nothing a host writes reaches either field: host text on
/// this channel reaches the client, browser history and proxy logs, so it would be a disclosure
/// primitive.
/// </para>
/// <para>
/// Each code tells the client only what the user did or already knows: that they cancelled, declined,
/// or were turned away after signing in elsewhere. None says whether an account exists or which
/// credential was wrong, and none names a provider. The description carries the same stage for
/// every client; the flag buys a stable value to branch on, not a secret.
/// </para>
/// </remarks>
internal sealed class Denial
{
    /// <summary>The response parameter the sub-code travels in. Clients must ignore what they do not recognise (RFC 6749 §4.1.2).</summary>
    public const string ZkdErrorParameter = "zkd_error";

    /// <summary>The user cancelled at the host's login page.</summary>
    public static readonly Denial CancelledAtSignIn = new(
        "The user cancelled the request at the sign-in page.", "login_cancelled");

    /// <summary>The user declined at the host's consent page.</summary>
    public static readonly Denial DeclinedAtConsent = new(
        "The user declined the request at the consent page.", "consent_declined");

    /// <summary>
    /// The user cancelled or refused at the external provider, when there is no login page to
    /// return to — with one, the user goes back there and the client is told nothing.
    /// </summary>
    public static readonly Denial DeclinedAtProvider = new(
        "The user declined to sign in at the external identity provider.", "provider_declined");

    /// <summary>The user signed in at the external provider and the host refused that account.</summary>
    public static readonly Denial RefusedAfterProvider = new(
        "The sign-in at the external identity provider was not accepted.", "account_refused");

    private Denial(string description, string zkdError)
    {
        Description = description;
        ZkdError = zkdError;
    }

    /// <summary>The <c>error_description</c>, sent to every client.</summary>
    public string Description { get; }

    /// <summary>The <c>zkd_error</c> value, sent only to a client that opted in.</summary>
    public string ZkdError { get; }
}
