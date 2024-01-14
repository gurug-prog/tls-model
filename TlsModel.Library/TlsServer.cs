using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TlsModel.Library.Extensions;
using TlsModel.Library.Helpers;

namespace TlsModel.Library;

public class TlsServer
{
    private readonly X509Certificate2 _serverCertificate;
    private readonly RSACryptoServiceProvider _serverRsa;
    private readonly string _storagePath;

    public TcpListener Server { get; private set; }

    public bool IsRunning { get; private set; }

    public TlsServer(int port, string storagePath)
    {
        Server = new TcpListener(IPAddress.Any, port);
        _storagePath = storagePath;
        _serverRsa = new RSACryptoServiceProvider(2048);
        _serverCertificate = GenerateServerCertificate(_serverRsa);
        //Server = new TcpListener(new IPAddress(new byte[] { 127, 0, 0, 1 }), port);
    }

    public TlsServer(byte[] ip, int port, string storagePath)
    {
        Server = new TcpListener(new IPAddress(ip), port);
        _storagePath = storagePath;
        _serverRsa = new RSACryptoServiceProvider(2048);
        _serverCertificate = GenerateServerCertificate(_serverRsa);
    }

    public async Task Listen()
    {
        IsRunning = true;
        Server.Start();
        Console.WriteLine("Server is listening on port 3000...");
        
        while (IsRunning)
        {
            var client = await Server.AcceptTcpClientAsync();
            await Task.Run(() =>
            {
                var clientStream = client.GetStream();
                var masterSecret = TlsHandshake(clientStream);
                HandleRequest(clientStream, masterSecret);
            });

            SynchronizeStorage();
            DriveBackup();
        }
    }

    public void Stop()
    {
        IsRunning = false;
        Server.Stop();
    }

    private byte[] TlsHandshake(NetworkStream clientStream)
    {
        // Step 1: Server receives "CLIENT_HELLO" message
        byte[] helloClientMessage = clientStream.ReceiveMessage();
        Console.WriteLine("Client says: " + Encoding.UTF8.GetString(helloClientMessage));
        var randomClient = ExtractRandomClient(helloClientMessage);

        // Step 2: Server responds with "SERVER_HELLO", SSL certificate, and random server value
        var randomServer = RandomHelper.GenerateRandomPrime(10_000_000, 100_000_000);
        byte[] helloServerMessage = BuildServerHelloMessage(
            randomServer,
            _serverCertificate.Export(X509ContentType.Pfx));
        clientStream.SendMessage(helloServerMessage);

        // Step 4: Server receives encrypted premaster secret from client
        byte[] encryptedPremaster = clientStream.ReceiveMessage();
        byte[] premasterSecret = DecryptPremasterSecret(encryptedPremaster);

        // Step 5: Generate session keys using TLS PRF
        var masterSecret = CryptoHelper.GenerateSessionKey(premasterSecret, randomServer, randomClient);

        // Step 6: Server and client exchange "Ready" messages encrypted with the session key
        byte[] encryptedReady = CryptoHelper.EncryptAes(Encoding.UTF8.GetBytes("SERVER_READY"), masterSecret);
        clientStream.SendMessage(encryptedReady);

        byte[] response = clientStream.ReceiveMessage();
        byte[] clientReady = CryptoHelper.DecryptAes(response, masterSecret);
        Console.WriteLine("Client says: " + Encoding.UTF8.GetString(clientReady));
        Console.WriteLine("Handshake completed. Secure communication established.");

        return masterSecret;
    }

    private void HandleRequest(NetworkStream clientStream, byte[] masterSecret)
    {

    }

    private void SynchronizeStorage()
    {

    }

    private void DriveBackup()
    {

    }

    private static byte[] BuildServerHelloMessage(int randomServer, byte[] sslCertificate)
    {
        return Encoding.UTF8.GetBytes("SERVER_HELLO")
            //.Concat(Encoding.UTF8.GetBytes(Environment.NewLine))
            .Concat(sslCertificate)
            //.Concat(Encoding.UTF8.GetBytes(Environment.NewLine))
            .Concat(BitConverter.GetBytes(randomServer))
            .ToArray();
    }

    private static int ExtractRandomClient(byte[] helloClientMessage)
    {
        string helloString = Encoding.UTF8.GetString(helloClientMessage);
        int index = helloString.IndexOf(Environment.NewLine, StringComparison.Ordinal) + Environment.NewLine.Length;
        string randomClientString = helloString.Substring(index);
        int randomClient = int.Parse(randomClientString);
        return randomClient;
    }

    private static X509Certificate2 GenerateServerCertificate(RSACryptoServiceProvider rsa)
    {
        // Generate a simple self-signed certificate using the provided RSA public key
        var request = new CertificateRequest("cn=MyTrustedCA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        DateTimeOffset notBefore = DateTime.UtcNow;
        DateTimeOffset notAfter = notBefore.AddYears(1);
        var certificate = request.CreateSelfSigned(notBefore, notAfter);

        return certificate;
    }

    private byte[] DecryptPremasterSecret(byte[] encryptedPremaster)
    {
        // Decrypt the premaster secret using server's private key
        using RSA privateRsa = RSA.Create();
        var privateKeyBytes = new ReadOnlySpan<byte>(_serverRsa.ExportRSAPrivateKey());
        privateRsa.ImportRSAPrivateKey(privateKeyBytes, out _);

        byte[] premasterSecret = privateRsa.Decrypt(encryptedPremaster, RSAEncryptionPadding.OaepSHA256);
        return premasterSecret;
    }
}
