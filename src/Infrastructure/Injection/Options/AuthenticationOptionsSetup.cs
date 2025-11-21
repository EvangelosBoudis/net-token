using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace Infrastructure.Injection.Options;

public class AuthenticationOptionsSetup : IConfigureOptions<AuthenticationOptions>
{
    private const string Scheme = JwtBearerDefaults.AuthenticationScheme;

    public void Configure(AuthenticationOptions options)
    {
        options.DefaultScheme = Scheme;
        options.DefaultChallengeScheme = Scheme;
        options.DefaultAuthenticateScheme = Scheme;
    }
}