using Application.Token.Data;
using Domain.Data;
using Domain.Entities;

namespace Application.Token;

public interface ITokenProvider
{
    string CreateAccessToken(User user);

    string CreateRefreshToken();

    TokenData CreateToken(User user);

    TokenDetails ReadAccessToken(string accessToken);
}