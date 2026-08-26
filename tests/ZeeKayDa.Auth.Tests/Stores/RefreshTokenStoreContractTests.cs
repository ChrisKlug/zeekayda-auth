using System.Reflection;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Verifies the type shape of <see cref="RefreshTokenEntry"/>, <see cref="RefreshTokenGrant"/>,
/// <see cref="RefreshGrantStatus"/>, <see cref="RefreshTokenConsumptionResult"/>, and
/// <see cref="IRefreshTokenStore"/>'s method signatures.
/// </summary>
public sealed class RefreshTokenStoreContractTests
{
    // ── RefreshTokenEntry — type shape ────────────────────────────────────────────────────────────

    [Fact]
    public void RefreshTokenEntry_FamilyId_is_a_required_init_only_property()
    {
        var prop = typeof(RefreshTokenEntry).GetProperty(nameof(RefreshTokenEntry.FamilyId));

        prop.Should().NotBeNull();

        var setter = prop!.GetSetMethod(nonPublic: false);
        setter.Should().NotBeNull("FamilyId must have a public setter");
        var isInitOnly = setter!.ReturnParameter
            .GetRequiredCustomModifiers()
            .Contains(typeof(System.Runtime.CompilerServices.IsExternalInit));
        isInitOnly.Should().BeTrue("FamilyId must be init-only");

        prop.GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>()
            .Should().NotBeNull("FamilyId must be required");
    }

    [Fact]
    public void RefreshTokenEntry_ClientId_is_a_required_init_only_property()
    {
        var prop = typeof(RefreshTokenEntry).GetProperty(nameof(RefreshTokenEntry.ClientId));

        prop.Should().NotBeNull();
        prop!.GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>()
            .Should().NotBeNull("ClientId must be required");
    }

    [Fact]
    public void RefreshTokenEntry_Sub_is_a_required_init_only_property()
    {
        var prop = typeof(RefreshTokenEntry).GetProperty(nameof(RefreshTokenEntry.Sub));

        prop.Should().NotBeNull();
        prop!.GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>()
            .Should().NotBeNull("Sub must be required");
    }

    [Fact]
    public void RefreshTokenEntry_Scope_is_a_required_init_only_property()
    {
        var prop = typeof(RefreshTokenEntry).GetProperty(nameof(RefreshTokenEntry.Scope));

        prop.Should().NotBeNull();
        prop!.GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>()
            .Should().NotBeNull("Scope must be required");
    }

    [Fact]
    public void RefreshTokenEntry_SsoSessionId_is_a_required_init_only_property()
    {
        var prop = typeof(RefreshTokenEntry).GetProperty(nameof(RefreshTokenEntry.SsoSessionId));

        prop.Should().NotBeNull();
        prop!.GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>()
            .Should().NotBeNull("SsoSessionId must be required");
    }

    [Fact]
    public void RefreshTokenEntry_IssuedAt_is_a_required_init_only_property()
    {
        var prop = typeof(RefreshTokenEntry).GetProperty(nameof(RefreshTokenEntry.IssuedAt));

        prop.Should().NotBeNull();
        prop!.PropertyType.Should().Be(typeof(DateTimeOffset));
        prop.GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>()
            .Should().NotBeNull("IssuedAt must be required");
    }

    [Fact]
    public void RefreshTokenEntry_ExpiresAt_is_a_required_init_only_property()
    {
        var prop = typeof(RefreshTokenEntry).GetProperty(nameof(RefreshTokenEntry.ExpiresAt));

        prop.Should().NotBeNull();
        prop!.PropertyType.Should().Be(typeof(DateTimeOffset));
        prop.GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>()
            .Should().NotBeNull("ExpiresAt must be required");
    }

    [Fact]
    public void RefreshTokenEntry_FamilyAbsoluteExpiry_is_a_required_init_only_property()
    {
        var prop = typeof(RefreshTokenEntry).GetProperty(nameof(RefreshTokenEntry.FamilyAbsoluteExpiry));

        prop.Should().NotBeNull();
        prop!.PropertyType.Should().Be(typeof(DateTimeOffset));
        prop.GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>()
            .Should().NotBeNull("FamilyAbsoluteExpiry must be required");
    }

    [Fact]
    public void RefreshTokenEntry_PreviousTokenHandleHash_is_nullable_and_not_required()
    {
        var prop = typeof(RefreshTokenEntry).GetProperty(nameof(RefreshTokenEntry.PreviousTokenHandleHash));

        prop.Should().NotBeNull();
        prop!.PropertyType.Should().Be(typeof(string));
        prop.GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>()
            .Should().BeNull("PreviousTokenHandleHash is optional");
    }

    // ── RefreshTokenConsumptionResult — type hierarchy ───────────────────────────────────────────

    [Fact]
    public void RefreshTokenConsumptionResult_has_exactly_one_constructor_and_it_is_private()
    {
        var allCtors = typeof(RefreshTokenConsumptionResult)
            .GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

        allCtors.Should().ContainSingle(
            "the type must have exactly one constructor to be a closed hierarchy");
        allCtors[0].IsPrivate.Should().BeTrue(
            "a private constructor prevents any subtype from being declared outside the assembly");
    }

    // ── RefreshTokenConsumptionResult — subtype properties ────────────────────────────────────────

    [Fact]
    public void Consumed_has_required_Entry_property_of_type_RefreshTokenEntry()
    {
        var prop = typeof(RefreshTokenConsumptionResult.Consumed)
            .GetProperty(nameof(RefreshTokenConsumptionResult.Consumed.Entry));

        prop.Should().NotBeNull();
        prop!.PropertyType.Should().Be(typeof(RefreshTokenEntry));
        prop.GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>()
            .Should().NotBeNull("Consumed.Entry must be required");
    }

    [Fact]
    public void AlreadyConsumed_has_required_FamilyId_property_of_type_string()
    {
        var prop = typeof(RefreshTokenConsumptionResult.AlreadyConsumed)
            .GetProperty(nameof(RefreshTokenConsumptionResult.AlreadyConsumed.FamilyId));

        prop.Should().NotBeNull();
        prop!.PropertyType.Should().Be(typeof(string));
        prop.GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>()
            .Should().NotBeNull("AlreadyConsumed.FamilyId must be required");
    }

    [Fact]
    public void Revoked_has_required_FamilyId_property_of_type_string()
    {
        var prop = typeof(RefreshTokenConsumptionResult.Revoked)
            .GetProperty(nameof(RefreshTokenConsumptionResult.Revoked.FamilyId));

        prop.Should().NotBeNull();
        prop!.PropertyType.Should().Be(typeof(string));
        prop.GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>()
            .Should().NotBeNull("Revoked.FamilyId must be required");
    }

    [Fact]
    public void ClientMismatch_has_no_additional_declared_properties()
    {
        var ownProps = typeof(RefreshTokenConsumptionResult.ClientMismatch)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

        ownProps.Should().BeEmpty();
    }

    [Fact]
    public void NotFound_has_no_additional_declared_properties()
    {
        var ownProps = typeof(RefreshTokenConsumptionResult.NotFound)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

        ownProps.Should().BeEmpty();
    }

    // ── RefreshTokenGrant — type shape ────────────────────────────────────────────────────────────

    [Fact]
    public void RefreshTokenGrant_HandleHash_is_of_type_StoreKey()
    {
        var prop = typeof(RefreshTokenGrant).GetProperty(nameof(RefreshTokenGrant.HandleHash));

        prop.Should().NotBeNull();
        prop!.PropertyType.Should().Be(typeof(StoreKey));
    }

    [Fact]
    public void RefreshTokenGrant_Subject_is_a_plain_string_not_a_StoreKey()
    {
        // Subject is deliberately cleartext, NOT an opaque hash — this was a deliberate reversal
        // of an earlier decision to hash it.
        var prop = typeof(RefreshTokenGrant).GetProperty(nameof(RefreshTokenGrant.Subject));

        prop.Should().NotBeNull();
        prop!.PropertyType.Should().Be(typeof(string));
    }

    [Fact]
    public void RefreshTokenGrant_FamilyId_is_a_plain_string_not_a_StoreKey()
    {
        var prop = typeof(RefreshTokenGrant).GetProperty(nameof(RefreshTokenGrant.FamilyId));

        prop.Should().NotBeNull();
        prop!.PropertyType.Should().Be(typeof(string));
    }

    [Fact]
    public void RefreshTokenGrant_ProtectedPayload_is_ReadOnlyMemory_of_byte()
    {
        var prop = typeof(RefreshTokenGrant).GetProperty(nameof(RefreshTokenGrant.ProtectedPayload));

        prop.Should().NotBeNull();
        prop!.PropertyType.Should().Be(typeof(ReadOnlyMemory<byte>));
    }

    [Fact]
    public void RefreshTokenGrant_Status_is_of_type_RefreshGrantStatus()
    {
        var prop = typeof(RefreshTokenGrant).GetProperty(nameof(RefreshTokenGrant.Status));

        prop.Should().NotBeNull();
        prop!.PropertyType.Should().Be(typeof(RefreshGrantStatus));
    }

    // ── RefreshGrantStatus — enum shape ────────────────────────────────────────────────────────────

    [Fact]
    public void RefreshGrantStatus_Active_is_zero()
    {
        ((int)RefreshGrantStatus.Active).Should().Be(0, "Active must be the enum default value");
    }

    // ── IRefreshTokenGrantStore — method signatures ───────────────────────────────────────────────

    [Fact]
    public void IRefreshTokenGrantStore_has_exactly_six_methods()
    {
        var methods = typeof(IRefreshTokenGrantStore).GetMethods(BindingFlags.Public | BindingFlags.Instance);

        methods.Should().HaveCount(6,
            "InsertAsync, FindByHandleAsync, TryMarkConsumedAsync, RevokeFamilyAsync, RevokeBySubjectAsync, " +
            "IsFamilyRevokedAsync (amended by issue #386)");
    }

}
