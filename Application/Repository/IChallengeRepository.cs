using Domain.Entities;

namespace Application.Repository;

public interface IChallengeRepository : ICrudRepository<Challenge, Guid>
{
    Task<Challenge> FindByKeyAsync(string key);
}