using System.Reflection;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Verifies the type shape of <see cref="RefreshTokenEntry"/>, <see cref="RefreshTokenGrant"/>,
/// <see cref="RefreshGrantStatus"/>, <see cref="RefreshTokenConsumptionResult"/>, and
/// <see cref="IRefreshTokenStore"/>'s method signatures (ADR 0014 §2/§10).
/// </summary>
public sealed class RefreshTokenStoreContractTests
{
    // ── RefreshTokenEntry — type shape ────────────────────────────────────────────────────────────

    [Fact]
    public void RefreshTokenEntry_is_a_sealed_record()
    {
        var type = typeof(RefreshTokenEntry);

        type.IsSealed.Should().BeTrue();
        type.IsValueType.Should().BeFalse();
        type.GetMethod("<Clone>$").Should().NotBeNull(
            "the presence of <Clone>$ is the canonical way to confirm a type is a record at runtime");
    }

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
            .Should().NotBeNull("FamilyAbsoluteExpiry must be required (ADR 0014 §10)");
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

    // ── RefreshTokenEntry — record equality and defaults ──────────────────────────────────────────

    [Fact]
    public void RefreshTokenEntry_two_instances_with_same_values_are_equal()
    {
        var now = DateTimeOffset.UtcNow;
        IReadOnlyList<string> scope = ["openid", "profile"];

        var a = BuildEntry(scope: scope, now: now);
        var b = BuildEntry(scope: scope, now: now);

        a.Should().Be(b);
        (a == b).Should().BeTrue();
    }

    [Fact]
    public void RefreshTokenEntry_two_instances_with_different_FamilyId_are_not_equal()
    {
        var a = BuildEntry();
        var b = a with { FamilyId = "fam-2" };

        a.Should().NotBe(b);
    }

    [Fact]
    public void RefreshTokenEntry_PreviousTokenHandleHash_defaults_to_null_when_not_set()
    {
        var entry = BuildEntry();

        entry.PreviousTokenHandleHash.Should().BeNull();
    }

    [Fact]
    public void RefreshTokenEntry_with_PreviousTokenHandleHash_set_equals_another_instance_with_same_hash()
    {
        var a = BuildEntry() with { PreviousTokenHandleHash = "abc123" };
        var b = a with { };

        a.Should().Be(b);
    }

    private static RefreshTokenEntry BuildEntry(IReadOnlyList<string>? scope = null, DateTimeOffset? now = null)
    {
        var n = now ?? DateTimeOffset.UtcNow;
        return new RefreshTokenEntry
        {
            FamilyId = "fam-1",
            ClientId = "client-1",
            Sub = "user-1",
            Scope = scope ?? ["openid"],
            SsoSessionId = "sso-1",
            IssuedAt = n,
            ExpiresAt = n.AddHours(1),
            FamilyAbsoluteExpiry = n.AddDays(90),
        };
    }

    // ── RefreshTokenConsumptionResult — type hierarchy (ADR 0014 §10 rename) ─────────────────────

    [Fact]
    public void RefreshTokenConsumptionResult_is_abstract()
    {
        typeof(RefreshTokenConsumptionResult).IsAbstract.Should().BeTrue();
    }

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

    [Fact]
    public void RefreshTokenConsumptionResult_Consumed_is_sealed()
    {
        typeof(RefreshTokenConsumptionResult.Consumed).IsSealed.Should().BeTrue();
    }

    [Fact]
    public void RefreshTokenConsumptionResult_ClientMismatch_is_sealed()
    {
        typeof(RefreshTokenConsumptionResult.ClientMismatch).IsSealed.Should().BeTrue();
    }

    [Fact]
    public void RefreshTokenConsumptionResult_AlreadyConsumed_is_sealed()
    {
        typeof(RefreshTokenConsumptionResult.AlreadyConsumed).IsSealed.Should().BeTrue();
    }

    [Fact]
    public void RefreshTokenConsumptionResult_Revoked_is_sealed()
    {
        typeof(RefreshTokenConsumptionResult.Revoked).IsSealed.Should().BeTrue();
    }

    [Fact]
    public void RefreshTokenConsumptionResult_NotFound_is_sealed()
    {
        typeof(RefreshTokenConsumptionResult.NotFound).IsSealed.Should().BeTrue();
    }

    [Fact]
    public void RefreshTokenConsumptionResult_Consumed_inherits_from_RefreshTokenConsumptionResult()
    {
        typeof(RefreshTokenConsumptionResult.Consumed).Should().BeAssignableTo<RefreshTokenConsumptionResult>();
    }

    [Fact]
    public void RefreshTokenConsumptionResult_ClientMismatch_inherits_from_RefreshTokenConsumptionResult()
    {
        typeof(RefreshTokenConsumptionResult.ClientMismatch).Should().BeAssignableTo<RefreshTokenConsumptionResult>();
    }

    [Fact]
    public void RefreshTokenConsumptionResult_AlreadyConsumed_inherits_from_RefreshTokenConsumptionResult()
    {
        typeof(RefreshTokenConsumptionResult.AlreadyConsumed).Should().BeAssignableTo<RefreshTokenConsumptionResult>();
    }

    [Fact]
    public void RefreshTokenConsumptionResult_Revoked_inherits_from_RefreshTokenConsumptionResult()
    {
        typeof(RefreshTokenConsumptionResult.Revoked).Should().BeAssignableTo<RefreshTokenConsumptionResult>();
    }

    [Fact]
    public void RefreshTokenConsumptionResult_NotFound_inherits_from_RefreshTokenConsumptionResult()
    {
        typeof(RefreshTokenConsumptionResult.NotFound).Should().BeAssignableTo<RefreshTokenConsumptionResult>();
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

    // ── RefreshTokenGrant — type shape (ADR 0014 §2) ──────────────────────────────────────────────

    [Fact]
    public void RefreshTokenGrant_is_a_sealed_record()
    {
        var type = typeof(RefreshTokenGrant);

        type.IsSealed.Should().BeTrue();
        type.GetMethod("<Clone>$").Should().NotBeNull();
    }

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
        // ADR 0014 sign-off item 1: Subject is deliberately cleartext, NOT an opaque hash.
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
    public void RefreshGrantStatus_has_exactly_three_members()
    {
        Enum.GetValues<RefreshGrantStatus>().Should().HaveCount(3);
    }

    [Fact]
    public void RefreshGrantStatus_Active_is_zero()
    {
        ((int)RefreshGrantStatus.Active).Should().Be(0, "Active must be the enum default value");
    }

    [Fact]
    public void RefreshGrantStatus_Consumed_and_Revoked_are_distinct_terminal_states()
    {
        ((int)RefreshGrantStatus.Consumed).Should().NotBe((int)RefreshGrantStatus.Revoked);
    }

    // ── IRefreshTokenStore — method signatures ────────────────────────────────────────────────────

    [Fact]
    public void IRefreshTokenStore_is_an_interface()
    {
        typeof(IRefreshTokenStore).IsInterface.Should().BeTrue();
    }

    [Fact]
    public void IRefreshTokenStore_StoreAsync_has_correct_signature()
    {
        var method = typeof(IRefreshTokenStore).GetMethod(
            nameof(IRefreshTokenStore.StoreAsync),
            new[] { typeof(string), typeof(RefreshTokenEntry), typeof(CancellationToken) });

        method.Should().NotBeNull("StoreAsync must be declared on IRefreshTokenStore");
        method!.ReturnType.Should().Be(typeof(Task), "StoreAsync must return Task (not ValueTask)");
    }

    [Fact]
    public void IRefreshTokenStore_FindAsync_has_correct_signature()
    {
        var method = typeof(IRefreshTokenStore).GetMethod(
            nameof(IRefreshTokenStore.FindAsync),
            new[] { typeof(string), typeof(CancellationToken) });

        method.Should().NotBeNull("FindAsync must be declared on IRefreshTokenStore");
        method!.ReturnType.Should().Be(typeof(ValueTask<RefreshTokenEntry?>));
    }

    [Fact]
    public void IRefreshTokenStore_TryConsumeAsync_has_correct_signature()
    {
        var method = typeof(IRefreshTokenStore).GetMethod(
            nameof(IRefreshTokenStore.TryConsumeAsync),
            new[] { typeof(string), typeof(string), typeof(CancellationToken) });

        method.Should().NotBeNull("TryConsumeAsync must be declared on IRefreshTokenStore");
        method!.ReturnType.Should().Be(typeof(ValueTask<RefreshTokenConsumptionResult>),
            "TryConsumeAsync must return ValueTask<RefreshTokenConsumptionResult> (ADR 0014 §10 rename)");
    }

    [Fact]
    public void IRefreshTokenStore_RevokeFamilyAsync_has_correct_signature()
    {
        var method = typeof(IRefreshTokenStore).GetMethod(
            nameof(IRefreshTokenStore.RevokeFamilyAsync),
            new[] { typeof(string), typeof(CancellationToken) });

        method.Should().NotBeNull("RevokeFamilyAsync must be declared on IRefreshTokenStore");
        method!.ReturnType.Should().Be(typeof(Task), "RevokeFamilyAsync must return Task (not ValueTask)");
    }

    [Fact]
    public void IRefreshTokenStore_has_exactly_four_public_methods()
    {
        var methods = typeof(IRefreshTokenStore).GetMethods(BindingFlags.Public | BindingFlags.Instance);

        methods.Should().HaveCount(4,
            "the public contract defines exactly four methods: StoreAsync, FindAsync, TryConsumeAsync, RevokeFamilyAsync; " +
            "SealAsFrameworkOwnedProtocol is internal and deliberately excluded from this count");
    }

    // ── IRefreshTokenGrantStore — method signatures (ADR 0014 §3) ─────────────────────────────────

    [Fact]
    public void IRefreshTokenGrantStore_is_an_interface()
    {
        typeof(IRefreshTokenGrantStore).IsInterface.Should().BeTrue();
    }

    [Fact]
    public void IRefreshTokenGrantStore_has_exactly_five_methods()
    {
        var methods = typeof(IRefreshTokenGrantStore).GetMethods(BindingFlags.Public | BindingFlags.Instance);

        methods.Should().HaveCount(5,
            "InsertAsync, FindByHandleAsync, TryMarkConsumedAsync, RevokeFamilyAsync, RevokeBySubjectAsync (ADR 0014 §3)");
    }

    [Fact]
    public void IRefreshTokenGrantStore_TryMarkConsumedAsync_returns_ValueTask_of_bool()
    {
        var method = typeof(IRefreshTokenGrantStore).GetMethod(
            nameof(IRefreshTokenGrantStore.TryMarkConsumedAsync),
            new[] { typeof(StoreKey), typeof(CancellationToken) });

        method.Should().NotBeNull();
        method!.ReturnType.Should().Be(typeof(ValueTask<bool>),
            "TryMarkConsumedAsync reports whether THIS call performed the CAS transition");
    }

    [Fact]
    public void IRefreshTokenGrantStore_FindByHandleAsync_returns_ValueTask_of_nullable_RefreshTokenGrant()
    {
        var method = typeof(IRefreshTokenGrantStore).GetMethod(
            nameof(IRefreshTokenGrantStore.FindByHandleAsync),
            new[] { typeof(StoreKey), typeof(CancellationToken) });

        method.Should().NotBeNull();
        method!.ReturnType.Should().Be(typeof(ValueTask<RefreshTokenGrant?>));
    }
}
