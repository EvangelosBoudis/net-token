using Application.Repository;
using Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Store.Repository;

public class UserRepository : RepositoryBase<User>, IUserRepository
{
    public UserRepository(DataContext context) : base(context)
    {
    }

    public async Task<bool> ExistsByUsernameOrEmailAsync(string username, string email)
    {
        var count = await Context
            .Set<User>()
            .Where(u => u.Username == username || u.Email == email)
            .CountAsync();

        return count > 0;
    }

    public async Task<User?> FindByIdNoTrackingAsync(Guid id)
    {
        return await Context
            .Set<User>()
            .AsNoTracking()
            .Where(u => u.Id == id)
            .Include(u => u.Account)
            .FirstOrDefaultAsync();
    }

    public async Task<User?> FindByIdAsync(Guid id)
    {
        return await Context
            .Set<User>()
            .Where(u => u.Id == id)
            .Include(u => u.Account)
            .Include(u => u.TwoFactorAuth)
            .FirstOrDefaultAsync();
    }

    public async Task<User?> FindByEmailAsync(string email)
    {
        return await Context
            .Set<User>()
            .Where(u => u.Email == email)
            .Include(u => u.Account)
            .Include(u => u.TwoFactorAuth)
            .FirstOrDefaultAsync();
    }
}