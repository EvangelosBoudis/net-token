using Domain.Entities;

namespace Application.Repository;

public interface IUserRepository : IRepositoryBase<User>
{
    Task<bool> ExistsByUsernameOrEmailAsync(string username, string email);

    Task<User?> FindByIdAsync(Guid id);

    Task<User?> FindByIdNoTrackingAsync(Guid id);

    Task<User?> FindByEmailAsync(string email);
}