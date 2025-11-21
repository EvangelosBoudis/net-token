using Application.Store.Repository;
using Domain.Entities;
using Domain.Exceptions;
using Microsoft.EntityFrameworkCore;

namespace Forteio.Identity.Store.Repository;

public class UserRepository : CrudRepository<User, Guid>, IUserRepository
{
    public UserRepository(DataContext context) : base(context)
    {
    }

    public async Task<bool> ExistsByUsernameOrEmailAsync(string username, string email)
    {
        return await ExistsAsync(u => u.Username == username || u.Email == email);
    }

    public new async Task<User> FindByIdAsync(Guid primaryKey)
    {
        var entity = await Context
            .Set<User>()
            .Where(u => u.Id == primaryKey)
            .Include(u => u.Account)
            .Include(u => u.TwoFactorAuth)
            .FirstOrDefaultAsync();

        if (entity is not null) return entity;
        throw new EntityNotFoundException<User>();
    }

    public async Task<User> FindByIdNoTrackingAsync(Guid primaryKey)
    {
        var entity = await Context
            .Set<User>()
            .AsNoTracking()
            .Where(u => u.Id == primaryKey)
            .Include(u => u.Account)
            .FirstOrDefaultAsync();

        if (entity is not null) return entity;
        throw new EntityNotFoundException<User>();
    }

    public async Task<User> FindByEmailAsync(string email)
    {
        var entity = await Context
            .Set<User>()
            .Where(u => u.Email == email)
            .Include(u => u.Account)
            .Include(u => u.TwoFactorAuth)
            .FirstOrDefaultAsync();

        if (entity is not null) return entity;
        throw new EntityNotFoundException<User>();
    }
}