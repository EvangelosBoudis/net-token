using Domain.Entities;

namespace Application.Repository;

public interface IChallengeRepository : IRepositoryBase<Challenge>
{
    Task<Challenge?> FindByKeyAsync(string key);
}