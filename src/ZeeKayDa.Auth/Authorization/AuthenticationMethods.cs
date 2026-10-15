namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// RFC 8176 authentication method reference values, reported to a relying party in the <c>amr</c> claim.
/// </summary>
/// <remarks>
/// <para>
/// The common RFC 8176 values, for example
/// <c>SignInAsync(user.Subject, AuthenticationMethods.Password)</c>. Nothing validates against the
/// list, so any other registry value is passed as its own string.
/// </para>
/// <para>
/// Report only what the user actually did: a relying party may gate a sensitive operation on
/// <see cref="MultiFactor"/>.
/// </para>
/// </remarks>
public static class AuthenticationMethods
{
    /// <summary>Password-based authentication (<c>pwd</c>).</summary>
    public const string Password = "pwd";

    /// <summary>
    /// Multiple-factor authentication (<c>mfa</c>). Report it alongside the individual factors, never
    /// instead of them (RFC 8176 §2); <see cref="Mfa"/> does that.
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
    /// A multiple-factor sign-in: <see cref="MultiFactor"/> followed by the factors it was made of, as
    /// RFC 8176 §2 asks.
    /// </summary>
    /// <param name="first">The first factor used.</param>
    /// <param name="second">The second factor; one factor is not multiple-factor.</param>
    /// <param name="rest">Any further factors.</param>
    /// <returns>
    /// <see cref="MultiFactor"/> followed by every factor given, in order, ready to pass to
    /// <c>LoginInteraction.SignInAsync</c>.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="rest"/> is <see langword="null"/>.</exception>
    public static string[] Mfa(string first, string second, params string[] rest)
    {
        ArgumentNullException.ThrowIfNull(rest);

        return [MultiFactor, first, second, .. rest];
    }
}
