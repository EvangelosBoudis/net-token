namespace Application.Notification.Data;

public record EmailDto(string Receiver, string Subject, string Content, bool Html = false, string? Sender = null);