namespace Domain.Entities;

public class Account
{
    public Guid Id { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public bool Confirmed { get; set; }

    public int FailedAccessAttempts { get; set; }

    public bool Locked { get; set; }

    public DateTime? LockEndAt { get; set; }

    public Guid UserId { get; init; }

    public virtual User User { get; set; } = default!;
}