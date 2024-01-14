using TlsModel.Library;

namespace TlsModel.Client;

public class Program
{
    public static void Main()
    {
        var client = new TlsClient("127.0.0.1", 3000);
        client.Connect();
        Thread.Sleep(100_000);
    }
}
