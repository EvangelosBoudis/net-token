namespace Domain.Entities;

public class RefreshToken
{
    public Guid Id { get; set; }

    public required string Value { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public bool Disabled { get; set; }

    public bool Revoked { get; set; }

    public required DateTime ExpiredAt { get; set; }

    public Guid UserId { get; init; }

    public virtual User User { get; set; } = default!;
}