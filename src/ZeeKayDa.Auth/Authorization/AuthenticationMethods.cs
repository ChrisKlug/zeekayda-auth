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
/// The registry is not closed. A method with no registered value — an in-house factor, or one
/// registered after this list was written — is passed as its own string, and nothing here
/// validates against the list. What matters is that the value is the truth about how the user
/// authenticated: a relying party may gate a sensitive operation on seeing
/// <see cref="MultiFactor"/>, so reporting a method that was not actually used defeats a control
/// on the other side of the wire.
/// </para>
/// </remarks>
public static class AuthenticationMethods
{
    /// <summary>Password-based authentication (<c>pwd</c>).</summary>
    public const string Password = "pwd";

    /// <summary>
    /// Multiple-factor authentication (<c>mfa</c>). RFC 8176 §2 asks that the individual factors
    /// be reported alongside it — <c>SignInAsync(user, AuthenticationMethods.MultiFactor,
    /// AuthenticationMethods.Password, AuthenticationMethods.OneTimePassword)</c>.
    /// </summary>
    public const string MultiFactor = "mfa";

    /// <summary>Multiple-channel authentication (<c>mca</c>): two or more distinct channels.</summary>
    public const string MultiChannel = "mca";

    /// <summary>One-time password (<c>otp</c>).</summary>
    public const string OneTimePassword = "otp";

    /// <summary>Confirmation by short message service (<c>sms</c>).</summary>
    public const string Sms = "sms";

    /// <summary>Confirmation by telephone call (<c>tel</c>).</summary>
    public const string Telephone = "tel";

    /// <summary>Personal identification number or pattern (<c>pin</c>).</summary>
    public const string Pin = "pin";

    /// <summary>Knowledge-based authentication (<c>kba</c>).</summary>
    public const string KnowledgeBased = "kba";

    /// <summary>Risk-based authentication (<c>rba</c>).</summary>
    public const string RiskBased = "rba";

    /// <summary>Proof-of-possession of a key (<c>pop</c>).</summary>
    public const string ProofOfPossession = "pop";

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

    /// <summary>Iris scan biometric (<c>iris</c>).</summary>
    public const string IrisScan = "iris";

    /// <summary>Retina scan biometric (<c>retina</c>).</summary>
    public const string RetinaScan = "retina";

    /// <summary>Voice biometric (<c>vbm</c>).</summary>
    public const string VoiceBiometric = "vbm";

    /// <summary>Geolocation information (<c>geo</c>).</summary>
    public const string Geolocation = "geo";

    /// <summary>
    /// User presence test (<c>user</c>) — evidence a person was present, not which person.
    /// </summary>
    public const string UserPresence = "user";
}
