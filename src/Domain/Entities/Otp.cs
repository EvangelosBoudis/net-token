using Domain.Enums;

namespace Domain.Entities;

public class Otp
{
    public Guid Id { get; set; }

    public required string Code { get; set; }

    public required OtpType Type { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public bool Redeemed { get; set; }

    public bool Disabled { get; set; }

    public required DateTime ExpiredAt { get; set; }

    public Guid UserId { get; set; }

    public virtual User User { get; set; } = default!;
}