using Domain.Entities;
using Domain.Enums;

namespace Application.Store.Repository;

public interface IOtpRepository : ICrudRepository<Otp, Guid>
{
    Task<Otp> FindByUserIdCodeAndTypeAsync(Guid userId, string code, OtpType type);

    Task UpdateAsDisabledActiveCodesAsync(Guid userId, OtpType type);
}