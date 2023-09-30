using Domain.Entities;
using Domain.Enums;

namespace Application.Store.Repository;

public interface IOtpRepository : ICrudRepository<Otp, Guid>
{
    Task<Otp> FindActiveByUserIdCodeAndTypeAsync(Guid userId, string code, OtpType type);

    Task UpdateAsDisabledActiveCodesAsync(Guid userId, OtpType type);
}