namespace Application.Notification.Exceptions;

public class NotificationException : Exception
{
    public NotificationException()
    {
    }

    public NotificationException(string? message) : base(message)
    {
    }
}