using Application.Authentication;
using Application.Keys;
using Application.Notification;
using Application.Notification.Data;
using Application.Password;
using Application.Store;
using Application.Token;
using Application.Token.Data;
using Forteio.Identity.Authentication;
using Forteio.Identity.Injection.Options;
using Forteio.Identity.Keys;
using Forteio.Identity.Notification;
using Forteio.Identity.Password;
using Forteio.Identity.Store;
using Forteio.Identity.Token;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Forteio.Identity.Injection.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        var connection = configuration.GetSection("Datasource").Get<string>()!;
        services.AddDbContext<DataContext>(options => { options.UseNpgsql(connection); });
        services.BuildServiceProvider().GetRequiredService<DataContext>().Database.Migrate();

        services.AddAuthentication().AddJwtBearer();

        services.Configure<MailOptions>(configuration.GetSection("Mail"));
        services.Configure<TokenOptions>(configuration.GetSection("Token"));

        services.ConfigureOptions<TokenBearerOptionsSetup>();
        services.ConfigureOptions<AuthenticationOptionsSetup>();

        services.AddTransient<IStore, Store.Store>();

        services.AddScoped<IPasswordHandler, PasswordHandler>();
        services.AddScoped<IKeysManager, KeysManager>();
        services.AddScoped<INotificationSender, NotificationSender>();
        services.AddScoped<ITokenProvider, TokenProvider>();
        services.AddScoped<IAuthService, AuthService>();

        return services;
    }
}