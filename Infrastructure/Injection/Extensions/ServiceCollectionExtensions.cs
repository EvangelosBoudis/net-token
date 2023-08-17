using Application.Authentication;
using Application.Keys;
using Application.Notification;
using Application.Notification.Data;
using Application.Password;
using Application.Repository;
using Application.Token;
using Application.Token.Data;
using Infrastructure.Authentication;
using Infrastructure.Injection.Options;
using Infrastructure.Keys;
using Infrastructure.Notification;
using Infrastructure.Password;
using Infrastructure.Store;
using Infrastructure.Store.Repository;
using Infrastructure.Token;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Infrastructure.Injection.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        var connection = configuration.GetSection("Datasource").Get<string>()!;
        services.AddDbContext<DataContext>(options => { options.UseSqlite(connection); });
        services.BuildServiceProvider().GetRequiredService<DataContext>().Database.MigrateAsync();

        services.AddAuthentication().AddJwtBearer();

        services.Configure<MailOptions>(configuration.GetSection("Mail"));
        services.Configure<TokenOptions>(configuration.GetSection("Token"));

        services.ConfigureOptions<TokenBearerOptionsSetup>();
        services.ConfigureOptions<AuthenticationOptionsSetup>();

        services.AddScoped<IChallengeRepository, ChallengeRepository>();
        services.AddScoped<IOtpRepository, OtpRepository>();
        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
        services.AddScoped<IUserRepository, UserRepository>();

        services.AddScoped<IPasswordHandler, PasswordHandler>();
        services.AddScoped<IKeysManager, KeysManager>();
        services.AddScoped<INotificationSender, NotificationSender>();
        services.AddScoped<ITokenProvider, TokenProvider>();
        services.AddScoped<IAuthService, AuthService>();

        return services;
    }
}