using Application.Store.Repository;
using Domain.Entities;
using Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Store.Repository;

public class OtpRepository : CrudRepository<Otp, Guid>, IOtpRepository
{
    public OtpRepository(DataContext context) : base(context)
    {
    }

    public async Task<Otp> FindActiveByUserIdCodeAndTypeAsync(Guid userId, string code, OtpType type)
    {
        return await FindAsync(
            t => t.UserId == userId && t.Type == type && t.Code == code && !t.Disabled && !t.Redeemed);
    }

    public async Task UpdateAsDisabledActiveCodesAsync(Guid userId, OtpType type)
    {
        await Context
            .Set<Otp>()
            .Where(t =>
                t.UserId == userId && t.Type == type &&
                t.ExpiredAt > DateTime.UtcNow && !t.Disabled && !t.Redeemed)
            .ExecuteUpdateAsync(set => set.SetProperty(t => t.Disabled, true));
    }
}