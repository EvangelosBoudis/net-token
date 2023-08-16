using Domain.Data;
using Domain.Entities;

namespace Application.Token;

public interface ITokenProvider
{
    TokenData Generate(User user);

    Guid ExtractUserId(string accessToken);
}