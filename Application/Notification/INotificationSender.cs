using Application.Notification.Data;

namespace Application.Notification;

public interface INotificationSender
{
    Task SendEmailAsync(EmailDto email);
}