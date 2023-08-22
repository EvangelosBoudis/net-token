using Domain.Entities;

namespace Application.Repository;

public interface IRefreshTokenRepository : ICrudRepository<RefreshToken, Guid>
{
    Task<RefreshToken> FindActiveByValueAsync(string value);

    Task UpdateAsRevokedAsync(Guid userId);
}