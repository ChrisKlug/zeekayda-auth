using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Tests.Configuration;

public sealed class ValidatedOptionsCheckTests
{
    [Fact]
    public void ThrowIfAnyInvalid_reports_every_registered_options_types_failures_in_one_exception()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaOptions<FirstOptions>();
        services.AddZeeKayDaOptions<SecondOptions>();
        services.AddSingleton<IValidateOptions<FirstOptions>>(new CodedValidator<FirstOptions>("test.first"));
        services.AddSingleton<IValidateOptions<SecondOptions>>(new CodedValidator<SecondOptions>("test.second"));

        var act = () => ValidatedOptionsCheck.ThrowIfAnyInvalid(services.BuildServiceProvider());

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Select(f => f.Code).Should().Equal("test.first", "test.second");
    }

    [Fact]
    public void ThrowIfAnyInvalid_returns_when_every_registered_options_type_is_valid()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaOptions<FirstOptions>();
        services.AddSingleton<IValidateOptions<FirstOptions>>(new CodedValidator<FirstOptions>(code: null));

        var act = () => ValidatedOptionsCheck.ThrowIfAnyInvalid(services.BuildServiceProvider());

        act.Should().NotThrow();
    }

    [Fact]
    public void ThrowIfAnyInvalid_ignores_options_not_registered_through_ZeeKayDa()
    {
        var services = new ServiceCollection();
        services.AddOptions<FirstOptions>();
        services.AddSingleton<IValidateOptions<FirstOptions>>(new CodedValidator<FirstOptions>("test.first"));

        var act = () => ValidatedOptionsCheck.ThrowIfAnyInvalid(services.BuildServiceProvider());

        act.Should().NotThrow();
    }

    [Fact]
    public void ThrowIfAnyInvalid_reports_an_uncoded_validator_as_options_invalid_without_quoting_its_text()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaOptions<FirstOptions>();
        services.AddSingleton<IValidateOptions<FirstOptions>>(new UncodedValidator<FirstOptions>("secret-looking text"));

        var act = () => ValidatedOptionsCheck.ThrowIfAnyInvalid(services.BuildServiceProvider());

        var exception = act.Should().Throw<ZeeKayDaConfigurationException>().Which;
        var failure = exception.AggregatedFailures.Should().ContainSingle().Which;
        failure.Code.Should().Be("configuration.options_invalid");
        failure.Message.Should().Contain(typeof(FirstOptions).FullName).And.NotContain("secret-looking text");
        exception.InnerException.Should().BeOfType<OptionsValidationException>()
            .Which.Failures.Should().ContainSingle("secret-looking text");
    }

    [Fact]
    public void ThrowIfAnyInvalid_carries_every_root_cause_when_several_options_types_have_one()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaOptions<FirstOptions>();
        services.AddZeeKayDaOptions<SecondOptions>();
        services.AddSingleton<IValidateOptions<FirstOptions>>(new UncodedValidator<FirstOptions>("first"));
        services.AddSingleton<IValidateOptions<SecondOptions>>(new UncodedValidator<SecondOptions>("second"));

        var act = () => ValidatedOptionsCheck.ThrowIfAnyInvalid(services.BuildServiceProvider());

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.InnerException.Should().BeOfType<AggregateException>()
            .Which.InnerExceptions.Should().HaveCount(2);
    }

    [Fact]
    public void ThrowIfAnyInvalid_validates_named_options_under_their_own_name()
    {
        var services = new ServiceCollection();
        services.AddOptions<FirstOptions>("tenant").ValidateWithZeeKayDa();
        services.AddSingleton<IValidateOptions<FirstOptions>>(new CodedValidator<FirstOptions>("test.first", onlyName: "tenant"));

        var act = () => ValidatedOptionsCheck.ThrowIfAnyInvalid(services.BuildServiceProvider());

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "test.first");
    }

    [Fact]
    public void ThrowIfAnyInvalid_reports_every_validator_of_one_options_type_when_the_first_throws()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaOptions<FirstOptions>();
        services.AddSingleton<IValidateOptions<FirstOptions>>(new CodedValidator<FirstOptions>("test.framework"));
        services.AddSingleton<IValidateOptions<FirstOptions>>(new CodedValidator<FirstOptions>("test.third_party"));
        services.AddSingleton<IValidateOptions<FirstOptions>>(new UncodedValidator<FirstOptions>("host rule"));

        var act = () => ValidatedOptionsCheck.ThrowIfAnyInvalid(services.BuildServiceProvider());

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Select(f => f.Code).Should()
            .Equal("test.framework", "test.third_party", "configuration.options_invalid");
    }

    [Fact]
    public void ThrowIfAnyInvalid_validates_the_options_as_configured()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaOptions<FirstOptions>()
            .Configure(options => options.Value = 1)
            .Validate(options => options.Value == 0, "Value must be zero.");

        var act = () => ValidatedOptionsCheck.ThrowIfAnyInvalid(services.BuildServiceProvider());

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "configuration.options_invalid");
    }

    [Fact]
    public void ThrowIfAnyInvalid_validates_the_instance_the_application_reads()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaOptions<FirstOptions>();
        var validator = new RecordingValidator();
        services.AddSingleton<IValidateOptions<FirstOptions>>(validator);
        using var provider = services.BuildServiceProvider();

        ValidatedOptionsCheck.ThrowIfAnyInvalid(provider);

        validator.Validated.Should().ContainSingle()
            .Which.Should().BeSameAs(provider.GetRequiredService<IOptionsMonitor<FirstOptions>>().CurrentValue);
    }

    [Fact]
    public void ThrowIfAnyInvalid_reports_the_read_failure_when_no_single_validator_reproduces_it()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaOptions<FirstOptions>();
        services.AddSingleton<IOptionsFactory<FirstOptions>, ThrowingFactory>();

        var act = () => ValidatedOptionsCheck.ThrowIfAnyInvalid(services.BuildServiceProvider());

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "test.factory");
    }

    [Fact]
    public void AddZeeKayDaOptions_called_twice_reports_the_options_failures_once()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaOptions<FirstOptions>();
        services.AddZeeKayDaOptions<FirstOptions>();
        services.AddSingleton<IValidateOptions<FirstOptions>>(new CodedValidator<FirstOptions>("test.first"));

        var act = () => ValidatedOptionsCheck.ThrowIfAnyInvalid(services.BuildServiceProvider());

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle();
    }

    [Fact]
    public void AddZeeKayDaOptions_leaves_startup_verification_to_AddZeeKayDaAuthCore()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaOptions<FirstOptions>();

        services.Should().NotContain(descriptor => descriptor.ServiceType == typeof(IHostedService));
        services.Should().NotContain(descriptor => descriptor.ServiceType == typeof(IStartupVerificationGate));
    }

    private sealed class FirstOptions
    {
        public int Value { get; set; }
    }

    private sealed class SecondOptions;

    private sealed class CodedValidator<TOptions>(string? code, string? onlyName = null) : IValidateOptions<TOptions>
        where TOptions : class
    {
        public ValidateOptionsResult Validate(string? name, TOptions options) =>
            code is null || (onlyName is not null && name != onlyName)
                ? ValidateOptionsResult.Success
                : throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(code, "Invalid."));
    }

    private sealed class RecordingValidator : IValidateOptions<FirstOptions>
    {
        public List<FirstOptions> Validated { get; } = [];

        public ValidateOptionsResult Validate(string? name, FirstOptions options)
        {
            Validated.Add(options);
            return ValidateOptionsResult.Success;
        }
    }

    private sealed class ThrowingFactory : IOptionsFactory<FirstOptions>
    {
        public FirstOptions Create(string name) =>
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure("test.factory", "Invalid."));
    }

    private sealed class UncodedValidator<TOptions>(string message) : IValidateOptions<TOptions>
        where TOptions : class
    {
        public ValidateOptionsResult Validate(string? name, TOptions options) => ValidateOptionsResult.Fail(message);
    }
}
