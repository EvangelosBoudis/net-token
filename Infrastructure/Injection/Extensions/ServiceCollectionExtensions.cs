using Application.Authentication;
using Application.Keys;
using Application.Notification;
using Application.Password;
using Application.Token;
using Infrastructure.Authentication;
using Infrastructure.Injection.Options;
using Infrastructure.Keys;
using Infrastructure.Notification;
using Infrastructure.Password;
using Infrastructure.Store;
using Infrastructure.Token;
using Microsoft.Extensions.DependencyInjection;

namespace Infrastructure.Injection.Extensions;

public static class ServiceCollectionExtensions
{
    public static void AddInfrastructure(this IServiceCollection services)
    {
        services.AddDbContext<DataContext>();

        services.AddAuthentication().AddJwtBearer();

        services.ConfigureOptions<TokenOptionsSetup>();
        services.ConfigureOptions<MailOptionsSetup>();

        services.ConfigureOptions<TokenBearerOptionsSetup>();
        services.ConfigureOptions<AuthenticationOptionsSetup>();

        services.AddScoped<IPasswordHandler, PasswordHandler>();
        services.AddScoped<IKeysManager, KeysManager>();
        services.AddScoped<INotificationSender, NotificationSender>();
        services.AddScoped<ITokenProvider, TokenProvider>();
        services.AddScoped<IAuthService, AuthService>();
    }
}