using System.Reflection;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

public sealed class RefreshTokenStoreContractTests
{
    // ── RefreshTokenEntry — type shape ────────────────────────────────────────────────────────────

    [Fact]
    public void RefreshTokenEntry_is_a_sealed_record()
    {
        var type = typeof(RefreshTokenEntry);

        type.IsSealed.Should().BeTrue();
        type.IsValueType.Should().BeFalse();

        // Records expose a compiler-synthesised <Clone>$ method; classes do not.
        type.GetMethod("<Clone>$").Should().NotBeNull(
            "the presence of <Clone>$ is the canonical way to confirm a type is a record at runtime");
    }

    [Fact]
    public void RefreshTokenEntry_FamilyId_is_a_required_init_only_property()
    {
        var prop = typeof(RefreshTokenEntry).GetProperty(nameof(RefreshTokenEntry.FamilyId));

        prop.Should().NotBeNull();

        // init-only setters carry an IsExternalInit modreq on the setter's return parameter
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
        // IReadOnlyList<string> uses reference equality; share the same instance so records compare equal.
        IReadOnlyList<string> scope = ["openid", "profile"];

        var a = new RefreshTokenEntry
        {
            FamilyId = "fam-1",
            ClientId = "client-1",
            Sub = "user-1",
            Scope = scope,
            SsoSessionId = "sso-1",
            IssuedAt = now,
            ExpiresAt = now.AddHours(1),
        };

        var b = new RefreshTokenEntry
        {
            FamilyId = "fam-1",
            ClientId = "client-1",
            Sub = "user-1",
            Scope = scope,
            SsoSessionId = "sso-1",
            IssuedAt = now,
            ExpiresAt = now.AddHours(1),
        };

        a.Should().Be(b);
        (a == b).Should().BeTrue();
    }

    [Fact]
    public void RefreshTokenEntry_two_instances_with_different_FamilyId_are_not_equal()
    {
        var now = DateTimeOffset.UtcNow;

        var a = new RefreshTokenEntry
        {
            FamilyId = "fam-1",
            ClientId = "client-1",
            Sub = "user-1",
            Scope = ["openid"],
            SsoSessionId = "sso-1",
            IssuedAt = now,
            ExpiresAt = now.AddHours(1),
        };

        var b = a with { FamilyId = "fam-2" };

        a.Should().NotBe(b);
    }

    [Fact]
    public void RefreshTokenEntry_PreviousTokenHandleHash_defaults_to_null_when_not_set()
    {
        var entry = new RefreshTokenEntry
        {
            FamilyId = "fam-1",
            ClientId = "client-1",
            Sub = "user-1",
            Scope = ["openid"],
            SsoSessionId = "sso-1",
            IssuedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
        };

        entry.PreviousTokenHandleHash.Should().BeNull();
    }

    [Fact]
    public void RefreshTokenEntry_with_PreviousTokenHandleHash_set_equals_another_instance_with_same_hash()
    {
        var now = DateTimeOffset.UtcNow;

        var a = new RefreshTokenEntry
        {
            FamilyId = "fam-1",
            ClientId = "client-1",
            Sub = "user-1",
            Scope = ["openid"],
            SsoSessionId = "sso-1",
            IssuedAt = now,
            ExpiresAt = now.AddHours(1),
            PreviousTokenHandleHash = "abc123",
        };

        var b = a with { };

        a.Should().Be(b);
    }

    // ── RefreshTokenConsumptionOutcome — type hierarchy ───────────────────────────────────────────

    [Fact]
    public void RefreshTokenConsumptionOutcome_is_abstract()
    {
        typeof(RefreshTokenConsumptionOutcome).IsAbstract.Should().BeTrue();
    }

    [Fact]
    public void RefreshTokenConsumptionOutcome_cannot_be_instantiated_directly()
    {
        var constructors = typeof(RefreshTokenConsumptionOutcome)
            .GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);

        // The only constructor must be private (sealing the hierarchy from outside)
        constructors.Should().ContainSingle(
            "the type must have exactly one constructor to be a closed hierarchy");
        constructors[0].IsPrivate.Should().BeTrue(
            "a private constructor prevents any subtype from being declared outside the assembly");
    }

    [Fact]
    public void RefreshTokenConsumptionOutcome_Consumed_is_sealed()
    {
        typeof(RefreshTokenConsumptionOutcome.Consumed).IsSealed.Should().BeTrue();
    }

    [Fact]
    public void RefreshTokenConsumptionOutcome_ClientMismatch_is_sealed()
    {
        typeof(RefreshTokenConsumptionOutcome.ClientMismatch).IsSealed.Should().BeTrue();
    }

    [Fact]
    public void RefreshTokenConsumptionOutcome_AlreadyConsumed_is_sealed()
    {
        typeof(RefreshTokenConsumptionOutcome.AlreadyConsumed).IsSealed.Should().BeTrue();
    }

    [Fact]
    public void RefreshTokenConsumptionOutcome_Revoked_is_sealed()
    {
        typeof(RefreshTokenConsumptionOutcome.Revoked).IsSealed.Should().BeTrue();
    }

    [Fact]
    public void RefreshTokenConsumptionOutcome_NotFound_is_sealed()
    {
        typeof(RefreshTokenConsumptionOutcome.NotFound).IsSealed.Should().BeTrue();
    }

    [Fact]
    public void RefreshTokenConsumptionOutcome_Consumed_inherits_from_RefreshTokenConsumptionOutcome()
    {
        typeof(RefreshTokenConsumptionOutcome.Consumed)
            .Should().BeAssignableTo<RefreshTokenConsumptionOutcome>();
    }

    [Fact]
    public void RefreshTokenConsumptionOutcome_ClientMismatch_inherits_from_RefreshTokenConsumptionOutcome()
    {
        typeof(RefreshTokenConsumptionOutcome.ClientMismatch)
            .Should().BeAssignableTo<RefreshTokenConsumptionOutcome>();
    }

    [Fact]
    public void RefreshTokenConsumptionOutcome_AlreadyConsumed_inherits_from_RefreshTokenConsumptionOutcome()
    {
        typeof(RefreshTokenConsumptionOutcome.AlreadyConsumed)
            .Should().BeAssignableTo<RefreshTokenConsumptionOutcome>();
    }

    [Fact]
    public void RefreshTokenConsumptionOutcome_Revoked_inherits_from_RefreshTokenConsumptionOutcome()
    {
        typeof(RefreshTokenConsumptionOutcome.Revoked)
            .Should().BeAssignableTo<RefreshTokenConsumptionOutcome>();
    }

    [Fact]
    public void RefreshTokenConsumptionOutcome_NotFound_inherits_from_RefreshTokenConsumptionOutcome()
    {
        typeof(RefreshTokenConsumptionOutcome.NotFound)
            .Should().BeAssignableTo<RefreshTokenConsumptionOutcome>();
    }

    // ── RefreshTokenConsumptionOutcome — subtype properties ───────────────────────────────────────

    [Fact]
    public void Consumed_has_required_Entry_property_of_type_RefreshTokenEntry()
    {
        var prop = typeof(RefreshTokenConsumptionOutcome.Consumed)
            .GetProperty(nameof(RefreshTokenConsumptionOutcome.Consumed.Entry));

        prop.Should().NotBeNull();
        prop!.PropertyType.Should().Be(typeof(RefreshTokenEntry));
        prop.GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>()
            .Should().NotBeNull("Consumed.Entry must be required");
    }

    [Fact]
    public void AlreadyConsumed_has_required_FamilyId_property_of_type_string()
    {
        var prop = typeof(RefreshTokenConsumptionOutcome.AlreadyConsumed)
            .GetProperty(nameof(RefreshTokenConsumptionOutcome.AlreadyConsumed.FamilyId));

        prop.Should().NotBeNull();
        prop!.PropertyType.Should().Be(typeof(string));
        prop.GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>()
            .Should().NotBeNull("AlreadyConsumed.FamilyId must be required");
    }

    [Fact]
    public void Revoked_has_required_FamilyId_property_of_type_string()
    {
        var prop = typeof(RefreshTokenConsumptionOutcome.Revoked)
            .GetProperty(nameof(RefreshTokenConsumptionOutcome.Revoked.FamilyId));

        prop.Should().NotBeNull();
        prop!.PropertyType.Should().Be(typeof(string));
        prop.GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>()
            .Should().NotBeNull("Revoked.FamilyId must be required");
    }

    [Fact]
    public void ClientMismatch_has_no_additional_declared_properties()
    {
        var ownProps = typeof(RefreshTokenConsumptionOutcome.ClientMismatch)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

        ownProps.Should().BeEmpty(
            "ClientMismatch carries no additional data beyond the base type");
    }

    [Fact]
    public void NotFound_has_no_additional_declared_properties()
    {
        var ownProps = typeof(RefreshTokenConsumptionOutcome.NotFound)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

        ownProps.Should().BeEmpty(
            "NotFound carries no additional data beyond the base type");
    }

    // ── RefreshTokenConsumptionOutcome — closed hierarchy enforcement ─────────────────────────────

    [Fact]
    public void RefreshTokenConsumptionOutcome_has_exactly_one_constructor_and_it_is_private()
    {
        var allCtors = typeof(RefreshTokenConsumptionOutcome)
            .GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

        allCtors.Should().ContainSingle();
        allCtors[0].IsPrivate.Should().BeTrue();
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
            new[] { typeof(RefreshTokenEntry), typeof(CancellationToken) });

        method.Should().NotBeNull("StoreAsync must be declared on IRefreshTokenStore");
        method!.ReturnType.Should().Be(typeof(Task),
            "StoreAsync must return Task (not ValueTask)");
    }

    [Fact]
    public void IRefreshTokenStore_FindAsync_has_correct_signature()
    {
        var method = typeof(IRefreshTokenStore).GetMethod(
            nameof(IRefreshTokenStore.FindAsync),
            new[] { typeof(string), typeof(CancellationToken) });

        method.Should().NotBeNull("FindAsync must be declared on IRefreshTokenStore");
        method!.ReturnType.Should().Be(typeof(ValueTask<RefreshTokenEntry?>),
            "FindAsync must return ValueTask<RefreshTokenEntry?>");
    }

    [Fact]
    public void IRefreshTokenStore_TryConsumeAsync_has_correct_signature()
    {
        var method = typeof(IRefreshTokenStore).GetMethod(
            nameof(IRefreshTokenStore.TryConsumeAsync),
            new[] { typeof(string), typeof(string), typeof(CancellationToken) });

        method.Should().NotBeNull("TryConsumeAsync must be declared on IRefreshTokenStore");
        method!.ReturnType.Should().Be(typeof(ValueTask<RefreshTokenConsumptionOutcome>),
            "TryConsumeAsync must return ValueTask<RefreshTokenConsumptionOutcome>");
    }

    [Fact]
    public void IRefreshTokenStore_RevokeFamilyAsync_has_correct_signature()
    {
        var method = typeof(IRefreshTokenStore).GetMethod(
            nameof(IRefreshTokenStore.RevokeFamilyAsync),
            new[] { typeof(string), typeof(CancellationToken) });

        method.Should().NotBeNull("RevokeFamilyAsync must be declared on IRefreshTokenStore");
        method!.ReturnType.Should().Be(typeof(Task),
            "RevokeFamilyAsync must return Task (not ValueTask)");
    }

    [Fact]
    public void IRefreshTokenStore_has_exactly_four_methods()
    {
        var methods = typeof(IRefreshTokenStore)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance);

        methods.Should().HaveCount(4,
            "the interface contract defines exactly four methods: StoreAsync, FindAsync, TryConsumeAsync, RevokeFamilyAsync");
    }
}
