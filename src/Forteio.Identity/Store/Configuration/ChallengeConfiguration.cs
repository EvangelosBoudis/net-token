using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Forteio.Identity.Store.Configuration;

public class ChallengeConfiguration : IEntityTypeConfiguration<Challenge>
{
    public void Configure(EntityTypeBuilder<Challenge> builder)
    {
        builder.ToTable("challenges");

        builder.HasKey(c => c.Id)
            .HasName("PK_challenges");

        builder
            .Property(c => c.Key)
            .HasColumnName("key");

        builder
            .Property(c => c.CreatedAt)
            .HasColumnName("created_at");

        builder
            .Property(c => c.Redeemed)
            .HasColumnName("redeemed");

        builder
            .Property(c => c.ExpiredAt)
            .HasColumnName("expired_at");

        builder
            .Property(c => c.TwoFactorAuthId)
            .HasColumnName("two_factor_auth_id");

        builder.HasOne(c => c.TwoFactorAuth)
            .WithMany(t => t.Challenges)
            .HasForeignKey(c => c.TwoFactorAuthId);
    }
}