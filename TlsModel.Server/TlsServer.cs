//using System.Net;
//using System.Net.Sockets;

//namespace TlsModel.Server;

//public class TlsServer
//{
//    private const int port = 3000;
//    private readonly IPAddress ipAddr = IPAddress.Parse("127.0.0.1");
//    private readonly TcpListener server;

//    public TlsServer()
//    {
//        server = new TcpListener(ipAddr, port);
//    }

//    public async Task Listen()
//    {
//        server.Start();
//        while (true)
//        {
//            using var tcpClient = await server.AcceptTcpClientAsync();
//        }
//    }
//}
