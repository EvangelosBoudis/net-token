namespace Application.Notification.Exceptions;

public class NotificationException : SystemException
{
    public NotificationException()
    {
    }

    public NotificationException(string? message) : base(message)
    {
    }
}