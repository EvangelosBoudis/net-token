namespace Domain.Entities;

public class TwoFactorAuth
{
    public Guid Id { get; set; }

    public bool Enabled { get; set; }

    public required string AuthenticatorKey { get; set; }

    public Guid UserId { get; init; }

    public virtual User User { get; set; } = default!;

    public virtual ICollection<Challenge> Challenges { get; set; } = new List<Challenge>();
}