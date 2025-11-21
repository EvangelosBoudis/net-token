using Application.Store;
using Application.Store.Repository;
using Forteio.Identity.Store.Repository;

namespace Forteio.Identity.Store;

public class Store : IStore
{
    private readonly DataContext _context;

    public Store(DataContext context)
    {
        _context = context;
        Challenges = new ChallengeRepository(_context);
        Otp = new OtpRepository(_context);
        RefreshTokens = new RefreshTokenRepository(_context);
        Users = new UserRepository(_context);
    }

    public IChallengeRepository Challenges { get; }

    public IOtpRepository Otp { get; }

    public IRefreshTokenRepository RefreshTokens { get; }

    public IUserRepository Users { get; }

    public async Task<int> FlushAsync()
    {
        return await _context.SaveChangesAsync();
    }

    public void Dispose()
    {
        _context.Dispose();
    }
}