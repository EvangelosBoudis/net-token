using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Store.Configuration;

public class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.ToTable("users");

        builder
            .HasKey(u => u.Id)
            .HasName("PK_users");

        builder
            .Property(u => u.Id)
            .HasColumnName("id");

        builder
            .Property(u => u.Username)
            .HasColumnName("username");

        builder
            .Property(u => u.Email)
            .HasColumnName("email");

        builder
            .Property(u => u.EmailConfirmed)
            .HasColumnName("email_confirmed");

        builder
            .Property(u => u.PhoneNumber)
            .HasColumnName("phone_number");

        builder
            .Property(u => u.PhoneNumberConfirmed)
            .HasColumnName("phone_number_confirmed");

        builder
            .Property(u => u.PasswordHash)
            .HasColumnName("password_hash");

        builder
            .Property(u => u.PasswordSalt)
            .HasColumnName("password_salt");

        builder.HasIndex(u => u.Email).IsUnique();
        builder.HasIndex(u => u.Username).IsUnique();

        builder
            .HasOne(u => u.Account)
            .WithOne(a => a.User)
            .HasForeignKey<Account>(a => a.UserId);

        builder
            .HasOne(u => u.TwoFactorAuth)
            .WithOne(t => t.User)
            .HasForeignKey<TwoFactorAuth>(t => t.UserId);

        builder
            .HasMany(u => u.RefreshTokens)
            .WithOne(t => t.User)
            .HasForeignKey(t => t.UserId);

        builder
            .HasMany(u => u.RefreshTokens)
            .WithOne(t => t.User)
            .HasForeignKey(t => t.UserId);
    }
}