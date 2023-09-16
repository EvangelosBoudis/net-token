using System.Reflection;
using Newtonsoft.Json;

namespace Infrastructure.XUnitTests.Utils;

public class TestUtil
{
    public MockData MockData { get; }

    public TestUtil()
    {
        var stream = Assembly
            .GetExecutingAssembly()
            .GetManifestResourceStream("Infrastructure.XUnitTests.Utils.mock.json")!;

        using var reader = new StreamReader(stream);
        var json = reader.ReadToEnd();
        MockData = JsonConvert.DeserializeObject<MockData>(json)!;
    }
}