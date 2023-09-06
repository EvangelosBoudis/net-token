using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Application.Token;
using Application.Token.Data;
using Application.Token.Exceptions;
using Domain.Data;
using Domain.Entities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Infrastructure.Token;

public class TokenProvider : ITokenProvider
{
    private readonly TokenOptions _options;
    private readonly SymmetricSecurityKey _securityKey;

    public TokenProvider(IOptions<TokenOptions> options)
    {
        _options = options.Value;
        _securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SecretKey));
    }

    public string GenerateAccessToken(User user)
    {
        var now = DateTime.UtcNow;

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.UniqueName, user.Username),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(JwtRegisteredClaimNames.Iat, $"{((DateTimeOffset)now).ToUnixTimeSeconds()}"),
            new(TokenClaimNames.PhoneNumber, user.PhoneNumber ?? string.Empty),
            new(TokenClaimNames.PhoneNumberVerified, user.PhoneNumberConfirmed.ToString().ToLower()),
            new(TokenClaimNames.TwoFactorEnabled, (user.TwoFactorAuth is { Enabled: true }).ToString().ToLower())
        };

        var signing = new SigningCredentials(_securityKey, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            _options.Issuer,
            _options.Audience,
            claims,
            now,
            DateTime.UtcNow.AddMinutes(_options.AccessExpirationInMinutes),
            signing);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public string GenerateRefreshToken()
    {
        var random = new byte[64];
        using var generator = RandomNumberGenerator.Create();
        generator.GetBytes(random);
        return Convert.ToBase64String(random);
    }

    public TokenData GenerateToken(User user) => new(GenerateAccessToken(user), GenerateRefreshToken());

    public TokenDetails ReadToken(string accessToken)
    {
        var token = ConvertToken(accessToken);
        var claims = token.Claims.ToDictionary(c => c.Type, c => c.Value);

        return new TokenDetails(
            token.Subject,
            token.Issuer,
            token.IssuedAt,
            token.Audiences.FirstOrDefault()!,
            token.ValidFrom,
            token.ValidTo,
            token.SignatureAlgorithm,
            claims[JwtRegisteredClaimNames.UniqueName],
            claims[JwtRegisteredClaimNames.Email],
            claims[TokenClaimNames.PhoneNumber],
            bool.Parse(claims[TokenClaimNames.PhoneNumberVerified]),
            bool.Parse(claims[TokenClaimNames.TwoFactorEnabled]));
    }

    private JwtSecurityToken ConvertToken(string accessToken)
    {
        try
        {
            var parameters = new TokenValidationParameters
            {
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _options.Issuer,
                ValidAudience = _options.Audience,
                IssuerSigningKey = _securityKey,
            };

            var handler = new JwtSecurityTokenHandler();
            handler.ValidateToken(accessToken, parameters, out var token);

            return (JwtSecurityToken)token;
        }
        catch (Exception error) when (error is ArgumentException or SecurityTokenException)
        {
            throw new InvalidTokenException(accessToken);
        }
    }
}