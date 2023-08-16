using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace Infrastructure.Injection.Options;

public class OptionsSetup<T> : IConfigureOptions<T> where T : class
{
    private readonly string _sectionName;
    private readonly IConfiguration _configuration;

    protected OptionsSetup(string sectionName, IConfiguration configuration)
    {
        _sectionName = sectionName;
        _configuration = configuration;
    }

    public void Configure(T options)
    {
        _configuration.GetSection(_sectionName).Bind(options);
    }
}