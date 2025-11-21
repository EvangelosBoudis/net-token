namespace Domain.Entities;

public class Challenge
{
    public Guid Id { get; set; }

    public required string Key { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public bool Redeemed { get; set; }

    public required DateTime ExpiredAt { get; set; }

    public Guid TwoFactorAuthId { get; init; }

    public virtual TwoFactorAuth TwoFactorAuth { get; set; } = default!;
}