using System.Net;
using System.Net.Mail;
using Application.Notification.Data;
using Application.Notification.Exceptions;

namespace Infrastructure.Notification;

public class NotificationSender
{
    private readonly MailOptions _options;

    public NotificationSender(MailOptions options)
    {
        _options = options;
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