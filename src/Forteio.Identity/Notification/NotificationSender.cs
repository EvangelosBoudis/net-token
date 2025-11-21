using System.Net;
using System.Net.Mail;
using Application.Notification;
using Application.Notification.Data;
using Application.Notification.Exceptions;
using Microsoft.Extensions.Options;

namespace Forteio.Identity.Notification;

public class NotificationSender : INotificationSender
{
    private readonly MailOptions _options;

    public NotificationSender(IOptions<MailOptions> options)
    {
        _options = options.Value;
    }

    public async Task SendEmailAsync(EmailDto email)
    {
        using var client = new SmtpClient(_options.Host, _options.Port);
        client.EnableSsl = true;
        client.UseDefaultCredentials = false;
        client.DeliveryMethod = SmtpDeliveryMethod.Network;
        client.Credentials = new NetworkCredential(_options.Username, _options.Password);

        try
        {
            using var message = new MailMessage(email.Sender ?? _options.Username, email.Receiver);
            message.Subject = email.Subject;
            message.Body = email.Content;
            message.IsBodyHtml = email.Html;

            await client.SendMailAsync(message);
        }
        catch (Exception error)
        {
            throw new NotificationException(error.Message);
        }
    }
}