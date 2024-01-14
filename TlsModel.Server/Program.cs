using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TlsModel.Server;

public class Program
{
    private static int _randomServer;
    private static int _randomClient;
    private static X509Certificate2 _serverCertificate;
    private static RSACryptoServiceProvider _serverRsa;

    private static byte[] _masterSecret;

    public static void Main()
    {
        var server = new TcpListener(IPAddress.Any, 3000);
        server.Start();
        Console.WriteLine("Server is listening on port 3000...");

        var client = server.AcceptTcpClient();
        var clientStream = client.GetStream();

        // Step 1: Server receives "CLIENT_HELLO" message
        byte[] helloClientMessage = ReceiveMessage(clientStream);
        Console.WriteLine("Client says: " + Encoding.UTF8.GetString(helloClientMessage));
        _randomClient = ExtractRandomClient(helloClientMessage);

        // Step 2: Server responds with "SERVER_HELLO", SSL certificate, and random server value
        _randomServer = GenerateRandomPrime(10_000_000, 100_000_000);
        _serverRsa = new RSACryptoServiceProvider(2048);
        _serverCertificate = GenerateServerCertificate(_serverRsa);
        byte[] helloServerMessage = BuildServerHelloMessage(
            _randomServer,
            _serverCertificate.Export(X509ContentType.Pfx));
        SendMessage(clientStream, helloServerMessage);

        // Step 4: Server receives encrypted premaster secret from client
        byte[] encryptedPremaster = ReceiveMessage(clientStream);
        byte[] premasterSecret = DecryptPremasterSecret(encryptedPremaster);

        // Step 5: Generate session keys using TLS PRF
        _masterSecret = GenerateSessionKey(premasterSecret, _randomServer, _randomClient);

        // Step 6: Server and client exchange "Ready" messages encrypted with the session key
        byte[] encryptedReady = EncryptAes(Encoding.UTF8.GetBytes("SERVER_READY"), _masterSecret);
        SendMessage(clientStream, encryptedReady);

        byte[] response = ReceiveMessage(clientStream);
        byte[] clientReady = DecryptAes(response, _masterSecret);
        Console.WriteLine("Client says: " + Encoding.UTF8.GetString(clientReady));


        //// Step 7: Server and client exchange "Ready" messages encrypted with the session key
        //byte[] readyMessage = Encrypt("Ready", masterSecretServer);
        //SendMessage(clientStream, readyMessage);

        Console.WriteLine("Handshake completed. Secure communication established.");

        // ... (the rest of the code remains unchanged)

        Thread.Sleep(100_000);
        server.Stop();
    }

    static byte[] BuildServerHelloMessage(int randomServer, byte[] sslCertificate)
    {
        return Encoding.UTF8.GetBytes("SERVER_HELLO")
            //.Concat(Encoding.UTF8.GetBytes(Environment.NewLine))
            .Concat(sslCertificate)
            //.Concat(Encoding.UTF8.GetBytes(Environment.NewLine))
            .Concat(BitConverter.GetBytes(randomServer))
            .ToArray();
    }

    static int ExtractRandomClient(byte[] helloClientMessage)
    {
        string helloString = Encoding.UTF8.GetString(helloClientMessage);
        int index = helloString.IndexOf(Environment.NewLine, StringComparison.Ordinal) + Environment.NewLine.Length;
        string randomClientString = helloString.Substring(index);
        int randomClient = int.Parse(randomClientString);
        return randomClient;
    }

    static X509Certificate2 GenerateServerCertificate(RSACryptoServiceProvider rsa)
    {
        // Generate a simple self-signed certificate using the provided RSA public key
        var request = new CertificateRequest("cn=MyTrustedCA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        DateTimeOffset notBefore = DateTime.UtcNow;
        DateTimeOffset notAfter = notBefore.AddYears(1);
        var certificate = request.CreateSelfSigned(notBefore, notAfter);

        return certificate;
    }

    static int GenerateRandomPrime(int min, int max)
    {
        var random = new Random();
        while (true)
        {
            int number = random.Next(min, max);
            if (IsPrime(number))
            {
                return number;
            }
        }
    }

    static bool IsPrime(int number)
    {
        if (number < 2)
        {
            return false;
        }

        for (int i = 2; i <= Math.Sqrt(number); i++)
        {
            if (number % i == 0)
            {
                return false;
            }
        }

        return true;
    }

    static void SendMessage(NetworkStream stream, byte[] message)
    {
        stream.Write(message, 0, message.Length);
    }

    static byte[] ReceiveMessage(NetworkStream stream)
    {
        byte[] buffer = new byte[4096];
        int bytesRead = stream.Read(buffer, 0, buffer.Length);
        byte[] message = new byte[bytesRead];
        Array.Copy(buffer, message, bytesRead);
        return message;
    }

    static byte[] DecryptPremasterSecret(byte[] encryptedPremaster)
    {
        // Decrypt the premaster secret using server's private key
        using RSA privateRsa = RSA.Create();
        var privateKeyBytes = new ReadOnlySpan<byte>(_serverRsa.ExportRSAPrivateKey());
        privateRsa.ImportRSAPrivateKey(privateKeyBytes, out _);

        byte[] premasterSecret = privateRsa.Decrypt(encryptedPremaster, RSAEncryptionPadding.OaepSHA256);
        return premasterSecret;
    }

    static byte[] GenerateSessionKey(byte[] premasterSecret, int randomServer, int randomClient)
    {
        byte[] inputKeyingMaterial = Concatenate(
            premasterSecret,
            BitConverter.GetBytes(randomServer),
            BitConverter.GetBytes(randomClient));

        using HMACSHA256 hmac = new HMACSHA256();
        byte[] sessionKey = HKDF(inputKeyingMaterial, 48, hmac);
        return sessionKey;
    }

    static byte[] Concatenate(params byte[][] arrays)
    {
        int totalLength = arrays.Sum(arr => arr.Length);
        byte[] result = new byte[totalLength];
        int offset = 0;
        foreach (byte[] array in arrays)
        {
            Buffer.BlockCopy(array, 0, result, offset, array.Length);
            offset += array.Length;
        }
        return result;
    }

    static byte[] HKDF(byte[] ikm, int length, HMAC hmac)
    {
        hmac.Key = new byte[hmac.HashSize / 8];
        byte[] prk = hmac.ComputeHash(Concatenate(new byte[] { 0x00 }, ikm));

        byte[] info = Encoding.UTF8.GetBytes("TLS key expansion");
        byte[] hmacInput = Concatenate(prk, info, new byte[] { 0x01 });
        byte[] okm = hmac.ComputeHash(hmacInput);

        byte[] result = new byte[32];
        Buffer.BlockCopy(okm, 0, result, 0, 32);
        return result;
    }

    static byte[] EncryptAes(byte[] data, byte[] key)
    {
        using Aes aesAlg = Aes.Create();
        aesAlg.Key = key;

        // Generate a random IV for CBC mode
        aesAlg.GenerateIV();

        using MemoryStream msEncrypt = new();
        using ICryptoTransform encryptor = aesAlg.CreateEncryptor();
        using CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write);
        csEncrypt.Write(data, 0, data.Length);
        csEncrypt.FlushFinalBlock();

        // Combine the IV and encrypted data
        byte[] result = new byte[aesAlg.IV.Length + msEncrypt.Length];
        Buffer.BlockCopy(aesAlg.IV, 0, result, 0, aesAlg.IV.Length);
        Buffer.BlockCopy(msEncrypt.ToArray(), 0, result, aesAlg.IV.Length, (int)msEncrypt.Length);

        return result;
    }

    static byte[] DecryptAes(byte[] encryptedData, byte[] key)
    {
        using Aes aesAlg = Aes.Create();
        // Extract IV from the beginning of the encrypted data
        byte[] iv = new byte[aesAlg.BlockSize / 8];
        Buffer.BlockCopy(encryptedData, 0, iv, 0, iv.Length);

        aesAlg.Key = key;
        aesAlg.IV = iv;

        using MemoryStream msDecrypt = new();
        using ICryptoTransform decryptor = aesAlg.CreateDecryptor();
        using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Write);
        // Start from index equal to IV length to skip IV during decryption
        csDecrypt.Write(encryptedData, iv.Length, encryptedData.Length - iv.Length);
        csDecrypt.FlushFinalBlock();

        return msDecrypt.ToArray();
    }
}
