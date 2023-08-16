using Application.Notification.Data;
using Microsoft.Extensions.Configuration;

namespace Infrastructure.Injection.Options;

public class MailOptionsSetup : OptionsSetup<MailOptions>
{
    private const string Mail = "Mail";

    public MailOptionsSetup(IConfiguration configuration) : base(Mail, configuration)
    {
    }
}