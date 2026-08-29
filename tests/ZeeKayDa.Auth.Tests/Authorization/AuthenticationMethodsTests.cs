using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.Tests.Authorization;

public sealed class AuthenticationMethodsTests
{
    [Fact]
    public void Mfa_leads_with_the_marker_and_keeps_the_factors_in_order()
    {
        // RFC 8176 §2 wants both: an RP seeing only "mfa" cannot tell a password and an
        // authenticator app from a password and an SMS.
        AuthenticationMethods.Mfa(AuthenticationMethods.Password, AuthenticationMethods.OneTimePassword)
            .Should().Equal(["mfa", "pwd", "otp"]);
    }

    [Fact]
    public void Mfa_carries_every_factor_beyond_the_first_two()
    {
        AuthenticationMethods.Mfa(
                AuthenticationMethods.Password,
                AuthenticationMethods.Fingerprint,
                AuthenticationMethods.HardwareKey,
                AuthenticationMethods.Sms)
            .Should().Equal(["mfa", "pwd", "fpt", "hwk", "sms"]);
    }

    [Fact]
    public void Mfa_does_not_deduplicate_what_the_caller_reported()
    {
        // The framework does not second-guess the host's account of how the user authenticated.
        // Reporting the same factor twice is odd, but silently rewriting an amr the host stated
        // would be the framework editing a security claim it has no evidence about.
        AuthenticationMethods.Mfa(AuthenticationMethods.Password, AuthenticationMethods.Password)
            .Should().Equal(["mfa", "pwd", "pwd"]);
    }
}
