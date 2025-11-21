using Application.Store.Repository;

namespace Application.Store;

public interface IStore : IDisposable
{
    IChallengeRepository Challenges { get; }

    IOtpRepository Otp { get; }

    IRefreshTokenRepository RefreshTokens { get; }

    IUserRepository Users { get; }

    Task<int> FlushAsync();
}