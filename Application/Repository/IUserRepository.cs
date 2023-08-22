using Domain.Entities;

namespace Application.Repository;

public interface IUserRepository : ICrudRepository<User, Guid>
{
    Task<bool> ExistsByUsernameOrEmailAsync(string username, string email);

    Task<User> FindByIdNoTrackingAsync(Guid primaryKey);

    Task<User> FindByEmailAsync(string email);
}