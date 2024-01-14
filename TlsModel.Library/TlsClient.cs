using System;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TlsModel.Library.Extensions;
using TlsModel.Library.Helpers;

namespace TlsModel.Library;

public class TlsClient
{
    private int _randomServer;
    private int _randomClient;
    private X509Certificate2 _serverCertificate;
    private byte[] _masterSecret;

    public TcpClient Client { get; private set; }

    public TlsClient(string ip, int port)
    {
        Client = new TcpClient(ip, port);
    }

    public void Connect()
    {
        var serverStream = Client.GetStream();

        // Step 1: Client send "CLIENT_HELLO" message
        _randomClient = RandomHelper.GenerateRandomPrime(10_000_000, 100_000_000);
        SendHelloClient(serverStream, _randomClient);

        // Step 2: Client receives "SERVER_HELLO" message
        byte[] serverResponse = serverStream.ReceiveMessage();
        ReceiveHelloServer(serverResponse);

        // Step 3: Verify Server SSL certificate
        if (!_serverCertificate.IsValid())
        {
            throw new Exception("Server SSL certificate is not valid");
        }

        // Step 4: Client generates and sends premasterSecret
        byte[] premasterSecret = RandomHelper.GenerateRandomBytes(48);
        byte[] encryptedPremaster = EncryptPremasterSecret(premasterSecret);
        serverStream.SendMessage(encryptedPremaster);

        // Step 5: Generate session keys using TLS PRF
        _masterSecret = CryptoHelper.GenerateSessionKey(premasterSecret, _randomServer, _randomClient);

        // Step 6: Server and client exchange "Ready" messages encrypted with the session key
        byte[] encryptedReady = CryptoHelper.EncryptAes(Encoding.UTF8.GetBytes("CLIENT_READY"), _masterSecret);
        serverStream.SendMessage(encryptedReady);

        byte[] response = serverStream.ReceiveMessage();
        byte[] serverReady = CryptoHelper.DecryptAes(response, _masterSecret);
        Console.WriteLine("Server says: " + Encoding.UTF8.GetString(serverReady));
        Console.WriteLine("Handshake completed. Secure communication established.");
    }

    public void Disconnect()
    {
        Client.Close();
    }

    private static void SendHelloClient(NetworkStream stream, int randomClient)
    {
        byte[] helloClientMessage = Encoding.UTF8.GetBytes("CLIENT_HELLO" + Environment.NewLine + randomClient);
        stream.SendMessage(helloClientMessage);
    }

    private void ReceiveHelloServer(byte[] serverResponse)
    {
        byte[] certificate = new byte[serverResponse.Length - Encoding.UTF8.GetBytes("SERVER_HELLO").Length - sizeof(int)];
        Array.Copy(serverResponse, Encoding.UTF8.GetBytes("SERVER_HELLO").Length, certificate, 0, certificate.Length);
        _serverCertificate = new X509Certificate2(certificate);
        _randomServer = BitConverter.ToInt32(serverResponse, serverResponse.Length - sizeof(int));
    }

    private byte[] EncryptPremasterSecret(byte[] premasterSecret)
    {
        using RSA rsa = _serverCertificate.GetRSAPublicKey()!;
        int keySize = rsa.KeySize / 8;
        if (premasterSecret.Length > keySize - 42)
        {
            throw new Exception("Data is too long to be encrypted with this key size.");
        }

        byte[] encryptedData = rsa.Encrypt(premasterSecret, RSAEncryptionPadding.OaepSHA256);
        return encryptedData;
    }
}
