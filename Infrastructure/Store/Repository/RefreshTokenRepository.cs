using Application.Repository;
using Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Store.Repository;

public class RefreshTokenRepository : RepositoryBase<RefreshToken>, IRefreshTokenRepository
{
    public RefreshTokenRepository(DataContext context) : base(context)
    {
    }

    public async Task<RefreshToken?> FindActiveByValue(string value)
    {
        return await Context
            .Set<RefreshToken>()
            .Where(t => t.Value == value && !t.Disabled && !t.Revoked)
            .FirstOrDefaultAsync();
    }

    public async Task UpdateAsRevokedAsync(Guid userId)
    {
        await Context
            .Set<RefreshToken>()
            .Where(r => r.UserId == userId && !r.Disabled && !r.Revoked)
            .ExecuteUpdateAsync(set => set.SetProperty(t => t.Revoked, true));
    }
}