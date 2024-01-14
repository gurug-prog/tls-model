using TlsModel.Library;

namespace TlsModel.Server;

public class Program
{
    public static async Task Main()
    {
        var server = new TlsServer(3000, "");
        await server.Listen();
    }
}
