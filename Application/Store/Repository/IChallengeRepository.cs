using Domain.Entities;

namespace Application.Store.Repository;

public interface IChallengeRepository : ICrudRepository<Challenge, Guid>
{
    Task<Challenge> FindByKeyAsync(string key);
}