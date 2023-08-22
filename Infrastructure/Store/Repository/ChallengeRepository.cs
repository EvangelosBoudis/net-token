using Application.Repository;
using Domain.Entities;
using Domain.Exceptions;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Store.Repository;

public class ChallengeRepository : CrudRepository<Challenge, Guid>, IChallengeRepository
{
    public ChallengeRepository(DataContext context) : base(context)
    {
    }

    public async Task<Challenge> FindByKeyAsync(string key)
    {
        var entity = await Context
            .Set<Challenge>()
            .Where(c => c.Key == key && !c.Redeemed)
            .Include(c => c.TwoFactorAuth.User.Account)
            .FirstOrDefaultAsync();

        if (entity is not null) return entity;
        throw new EntityNotFoundException<Challenge>();
    }
}