using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Store.Configuration;

public class TwoFactorAuthConfiguration : IEntityTypeConfiguration<TwoFactorAuth>
{
    public void Configure(EntityTypeBuilder<TwoFactorAuth> builder)
    {
        builder.ToTable("two_factor_authentications");

        builder
            .HasKey(t => t.Id)
            .HasName("PK_two_factor_authentications");

        builder
            .Property(t => t.Id)
            .HasColumnName("id");

        builder
            .Property(t => t.Enabled)
            .HasColumnName("enabled");

        builder
            .Property(t => t.AuthenticatorKey)
            .HasColumnName("authenticator_key");

        builder
            .Property(t => t.UserId)
            .HasColumnName("user_id");

        builder
            .HasOne(t => t.User)
            .WithOne(u => u.TwoFactorAuth);

        builder
            .HasMany(t => t.Challenges)
            .WithOne(c => c.TwoFactorAuth)
            .HasForeignKey(c => c.TwoFactorAuthId);
    }
}