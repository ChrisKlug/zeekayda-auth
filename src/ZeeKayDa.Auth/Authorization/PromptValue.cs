using System.Text.Json.Serialization;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// OpenID Connect <c>prompt</c> parameter values, as defined in
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">
/// OpenID Connect Core 1.0 §3.1.2.1</see>.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<PromptValue>))]
public enum PromptValue
{
    /// <summary>
    /// Do not display any authentication or consent UI pages (<c>none</c>).
    /// The authorization server returns an error if the end-user is not already authenticated or
    /// consent cannot be obtained without interaction.
    /// </summary>
    [JsonStringEnumMemberName("none")]
    None,

    /// <summary>
    /// Prompt the end-user for reauthentication (<c>login</c>).
    /// If the end-user cannot be reauthenticated the authorization server returns an error.
    /// </summary>
    [JsonStringEnumMemberName("login")]
    Login,

    /// <summary>
    /// Prompt the end-user for consent before returning information to the client (<c>consent</c>).
    /// If consent cannot be obtained the authorization server returns an error.
    /// </summary>
    [JsonStringEnumMemberName("consent")]
    Consent,

    /// <summary>
    /// Prompt the end-user to select a user account (<c>select_account</c>).
    /// If the end-user cannot select an account the authorization server returns an error.
    /// </summary>
    [JsonStringEnumMemberName("select_account")]
    SelectAccount,
}
