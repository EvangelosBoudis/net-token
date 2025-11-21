using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Forteio.Identity.Store.Configuration;

public class OtpConfiguration : IEntityTypeConfiguration<Otp>
{
    public void Configure(EntityTypeBuilder<Otp> builder)
    {
        builder.ToTable("one_time_passwords");

        builder
            .HasKey(t => t.Id)
            .HasName("PK_one_time_passwords");

        builder
            .Property(t => t.Id)
            .HasColumnName("id");

        builder
            .Property(t => t.Code)
            .HasColumnName("code");

        builder
            .Property(t => t.Type)
            .HasColumnName("type");

        builder
            .Property(t => t.CreatedAt)
            .HasColumnName("created_at");

        builder
            .Property(t => t.Redeemed)
            .HasColumnName("redeemed");

        builder
            .Property(t => t.Disabled)
            .HasColumnName("disabled");

        builder
            .Property(t => t.ExpiredAt)
            .HasColumnName("expired_at");

        builder
            .Property(t => t.UserId)
            .HasColumnName("user_id");

        builder.HasOne(t => t.User)
            .WithMany(u => u.OneTimePasswords)
            .HasForeignKey(t => t.UserId);
    }
}