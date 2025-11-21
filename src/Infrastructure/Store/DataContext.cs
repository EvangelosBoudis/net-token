using Domain.Entities;
using Infrastructure.Store.Configuration;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Store;

public class DataContext : DbContext
{
    public DataContext(DbContextOptions options) : base(options)
    {
    }

    public virtual DbSet<User> Users { get; set; }

    public virtual DbSet<Account> Accounts { get; set; }

    public virtual DbSet<TwoFactorAuth> TwoFactorAuths { get; set; }

    public virtual DbSet<RefreshToken> RefreshTokens { get; set; }

    public virtual DbSet<Otp> OneTimePasswords { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.ApplyConfigurationsFromAssembly(typeof(UserConfiguration).Assembly);
        builder.ApplyConfigurationsFromAssembly(typeof(AccountConfiguration).Assembly);
        builder.ApplyConfigurationsFromAssembly(typeof(TwoFactorAuthConfiguration).Assembly);
        builder.ApplyConfigurationsFromAssembly(typeof(RefreshTokenConfiguration).Assembly);
        builder.ApplyConfigurationsFromAssembly(typeof(OtpConfiguration).Assembly);
    }
}