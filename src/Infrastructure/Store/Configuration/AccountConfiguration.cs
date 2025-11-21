using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Store.Configuration;

public class AccountConfiguration : IEntityTypeConfiguration<Account>
{
    public void Configure(EntityTypeBuilder<Account> builder)
    {
        builder.ToTable("accounts");

        builder.HasKey(a => a.Id)
            .HasName("PK_accounts");

        builder
            .Property(a => a.Id)
            .HasColumnName("id");

        builder
            .Property(a => a.CreatedAt)
            .HasColumnName("created_at");

        builder
            .Property(a => a.Confirmed)
            .HasColumnName("confirmed");

        builder
            .Property(a => a.FailedAccessAttempts)
            .HasColumnName("failed_access_attempts");

        builder
            .Property(a => a.Locked)
            .HasColumnName("locked");

        builder
            .Property(a => a.LockEndAt)
            .HasColumnName("lock_end_at");

        builder
            .Property(a => a.UserId)
            .HasColumnName("user_id");

        builder
            .HasOne(a => a.User)
            .WithOne(u => u.Account);
    }
}