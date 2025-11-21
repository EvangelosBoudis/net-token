using Application.Store.Repository;
using Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Store.Repository;

public class RefreshTokenRepository : CrudRepository<RefreshToken, Guid>, IRefreshTokenRepository
{
    public RefreshTokenRepository(DataContext context) : base(context)
    {
    }

    public async Task<RefreshToken> FindActiveByValueAsync(string value)
    {
        return await FindAsync(t => t.Value == value && !t.Disabled && !t.Revoked);
    }

    public async Task UpdateAsRevokedAsync(Guid userId)
    {
        await Context
            .Set<RefreshToken>()
            .Where(r => r.UserId == userId && !r.Disabled && !r.Revoked)
            .ExecuteUpdateAsync(set => set.SetProperty(t => t.Revoked, true));
    }
}