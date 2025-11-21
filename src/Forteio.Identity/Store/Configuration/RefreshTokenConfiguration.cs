using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Forteio.Identity.Store.Configuration;

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("refresh_tokens");

        builder
            .HasKey(t => t.Id)
            .HasName("PK_refresh_tokens");

        builder
            .Property(t => t.Id)
            .HasColumnName("id");

        builder
            .Property(t => t.Value)
            .HasColumnName("value");

        builder
            .Property(t => t.CreatedAt)
            .HasColumnName("created_at");

        builder
            .Property(t => t.Disabled)
            .HasColumnName("disabled");

        builder
            .Property(t => t.Revoked)
            .HasColumnName("revoked");

        builder
            .Property(t => t.ExpiredAt)
            .HasColumnName("expired_at");

        builder
            .Property(t => t.UserId)
            .HasColumnName("user_id");

        builder.HasOne(t => t.User)
            .WithMany(u => u.RefreshTokens)
            .HasForeignKey(t => t.UserId);
    }
}