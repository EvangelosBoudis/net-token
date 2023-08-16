using Application.Token.Data;
using Microsoft.Extensions.Configuration;

namespace Infrastructure.Injection.Options;

public class TokenOptionsSetup : OptionsSetup<TokenOptions>
{
    private const string Token = "Token";

    public TokenOptionsSetup(IConfiguration configuration) : base(Token, configuration)
    {
    }
}