using Application.Repository;
using Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Store.Repository;

public class ChallengeRepository : RepositoryBase<Challenge>, IChallengeRepository
{
    public ChallengeRepository(DataContext context) : base(context)
    {
    }

    public async Task<Challenge?> FindByKeyAsync(string key)
    {
        return await Context
            .Set<Challenge>()
            .Where(c => c.Key == key && !c.Redeemed)
            .Include(c => c.TwoFactorAuth.User.Account)
            .FirstOrDefaultAsync();
    }
}