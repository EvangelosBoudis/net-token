using Domain.Entities;

namespace Application.Repository;

public interface IRefreshTokenRepository : IRepositoryBase<RefreshToken>
{
    Task<RefreshToken?> FindActiveByValue(string value);

    Task UpdateAsRevokedAsync(Guid userId);
}