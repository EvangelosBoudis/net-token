namespace Domain.Entities;

public class User
{
    public Guid Id { get; set; }

    public required string Username { get; set; }

    public required string Email { get; set; }

    public bool EmailConfirmed { get; set; }

    public string? PhoneNumber { get; set; }

    public bool PhoneNumberConfirmed { get; set; }

    public required string PasswordHash { get; set; }

    public required string PasswordSalt { get; set; }

    public virtual required Account Account { get; set; } = default!;

    public virtual TwoFactorAuth? TwoFactorAuth { get; set; }

    public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();

    public virtual ICollection<Otp> OneTimePasswords { get; set; } = new List<Otp>();
}