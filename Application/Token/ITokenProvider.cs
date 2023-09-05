using Domain.Data;
using Domain.Entities;

namespace Application.Token;

public interface ITokenProvider
{
    string GenerateAccessToken(User user);

    string GenerateRefreshToken();

    TokenData GenerateToken(User user);

    string GetTokenSubject(string accessToken);
}