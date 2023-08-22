using Domain.Entities;

namespace Application.Store.Repository;

public interface IRefreshTokenRepository : ICrudRepository<RefreshToken, Guid>
{
    Task<RefreshToken> FindActiveByValueAsync(string value);

    Task UpdateAsRevokedAsync(Guid userId);
}