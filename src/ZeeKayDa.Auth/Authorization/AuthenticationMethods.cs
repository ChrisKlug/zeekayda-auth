namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// The authentication method reference values registered by RFC 8176 — how a user proved who they
/// are, as reported to a relying party in the <c>amr</c> claim.
/// </summary>
/// <remarks>
/// <para>
/// These exist so a host never has to know that the claim is spelled <c>amr</c> or that a password
/// is spelled <c>pwd</c>. Pass them to
/// <c>ILoginInteraction.SignInAsync</c>: <c>SignInAsync(user, AuthenticationMethods.Password)</c>.
/// </para>
/// <para>
/// These are the values with real-world traction, not the whole of RFC 8176 — the registry also
/// defines <c>iris</c>, <c>retina</c>, <c>vbm</c>, <c>geo</c>, <c>pop</c>, <c>mca</c>, <c>kba</c>,
/// <c>rba</c> and <c>user</c>, which are omitted deliberately. Nothing validates against this list,
/// so any of those is passed as its own string; a deployment using one knows what it is called.
/// The point of the constants is that the common case is discoverable, not that the set is
/// complete.
/// </para>
/// <para>
/// What matters either way is that the value is the truth about how the user authenticated: a
/// relying party may gate a sensitive operation on seeing <see cref="MultiFactor"/>, so reporting
/// a method that was not actually used defeats a control on the other side of the wire.
/// </para>
/// </remarks>
public static class AuthenticationMethods
{
    /// <summary>Password-based authentication (<c>pwd</c>).</summary>
    public const string Password = "pwd";

    /// <summary>
    /// Multiple-factor authentication (<c>mfa</c>). Report it <em>alongside</em> the individual
    /// factors, never instead of them — RFC 8176 §2 asks for both, and a relying party that sees
    /// only <c>mfa</c> cannot tell a password and an authenticator app from a password and an SMS.
    /// There is deliberately no constant for a particular combination: the spec names none, the
    /// set is open, and a named pair would hide the factors that are the useful part.
    /// <code>
    /// await login.SignInAsync(
    ///     user,
    ///     AuthenticationMethods.MultiFactor,
    ///     AuthenticationMethods.Password,
    ///     AuthenticationMethods.OneTimePassword);
    /// </code>
    /// </summary>
    public const string MultiFactor = "mfa";

    /// <summary>One-time password (<c>otp</c>).</summary>
    public const string OneTimePassword = "otp";

    /// <summary>Confirmation by short message service (<c>sms</c>).</summary>
    public const string Sms = "sms";

    /// <summary>Confirmation by telephone call (<c>tel</c>).</summary>
    public const string Telephone = "tel";

    /// <summary>Personal identification number or pattern (<c>pin</c>).</summary>
    public const string Pin = "pin";

    /// <summary>Proof-of-possession of a hardware-secured key (<c>hwk</c>).</summary>
    public const string HardwareKey = "hwk";

    /// <summary>Proof-of-possession of a software-secured key (<c>swk</c>).</summary>
    public const string SoftwareKey = "swk";

    /// <summary>Smart card (<c>sc</c>).</summary>
    public const string SmartCard = "sc";

    /// <summary>Windows integrated authentication (<c>wia</c>).</summary>
    public const string WindowsIntegrated = "wia";

    /// <summary>Fingerprint biometric (<c>fpt</c>).</summary>
    public const string Fingerprint = "fpt";

    /// <summary>Facial recognition (<c>face</c>).</summary>
    public const string FacialRecognition = "face";

    /// <summary>
    /// A multiple-factor sign-in: <see cref="MultiFactor"/> followed by the factors it was made
    /// of, which is the pairing RFC 8176 §2 asks for and the one that is easy to get half right
    /// by hand.
    /// </summary>
    /// <param name="first">The first factor used.</param>
    /// <param name="second">
    /// The second factor. Two is the minimum because one factor is not multiple-factor, and the
    /// signature is what enforces that rather than a remark asking the caller to remember.
    /// </param>
    /// <param name="rest">Any further factors.</param>
    /// <returns>
    /// <see cref="MultiFactor"/> followed by every factor given, in order, ready to pass straight
    /// to <c>ILoginInteraction.SignInAsync</c>:
    /// <code>
    /// await login.SignInAsync(
    ///     user,
    ///     AuthenticationMethods.Mfa(
    ///         AuthenticationMethods.Password,
    ///         AuthenticationMethods.OneTimePassword));
    /// </code>
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="rest"/> is <see langword="null"/>.</exception>
    public static string[] Mfa(string first, string second, params string[] rest)
    {
        ArgumentNullException.ThrowIfNull(rest);

        return [MultiFactor, first, second, .. rest];
    }
}
