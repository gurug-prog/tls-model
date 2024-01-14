using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TlsModel.Client;

public class Program
{
    private static int _randomServer;
    private static int _randomClient;
    private static X509Certificate2 _serverCertificate;

    private static byte[] _masterSecret;

    public static void Main()
    {
        var client = new TcpClient("127.0.0.1", 3000);
        var serverStream = client.GetStream();

        // Step 1: Client send "CLIENT_HELLO" message
        _randomClient = GenerateRandomPrime(10_000_000, 100_000_000);
        SendHelloClient(serverStream, _randomClient);

        // Step 2: Client receives "SERVER_HELLO" message
        byte[] serverResponse = ReceiveMessage(serverStream);
        ReceiveHelloServer(serverResponse);

        // Step 3: Verify Server SSL certificate
        if (!_serverCertificate.IsValid())
        {
            throw new Exception("Server SSL certificate is not valid");
        }

        // Step 4: Client generates and sends premasterSecret
        byte[] premasterSecret = GenerateRandomBytes(48);
        byte[] encryptedPremaster = EncryptPremasterSecret(premasterSecret);
        SendMessage(serverStream, encryptedPremaster);

        // Step 5: Generate session keys using TLS PRF
        _masterSecret = GenerateSessionKey(premasterSecret, _randomServer, _randomClient);

        // Step 6: Server and client exchange "Ready" messages encrypted with the session key
        byte[] encryptedReady = EncryptAes(Encoding.UTF8.GetBytes("CLIENT_READY"), _masterSecret);
        SendMessage(serverStream, encryptedReady);

        byte[] response = ReceiveMessage(serverStream);
        byte[] serverReady = DecryptAes(response, _masterSecret);
        Console.WriteLine("Server says: " + Encoding.UTF8.GetString(serverReady));


        //byte[] readyMessage = ReceiveMessage(stream);
        //string decryptedMessage = Decrypt(readyMessage, GenerateSessionKey(premasterSecret, _randomServer, _randomClient));
        //Console.WriteLine("Server says: " + decryptedMessage);

        Console.WriteLine("Handshake completed. Secure communication established.");

        Thread.Sleep(100_000);
        client.Close();
    }

    static void SendHelloClient(NetworkStream stream, int randomClient)
    {
        byte[] helloClientMessage = Encoding.UTF8.GetBytes("CLIENT_HELLO" + Environment.NewLine + randomClient);
        SendMessage(stream, helloClientMessage);
    }

    static void ReceiveHelloServer(byte[] serverResponse)
    {
        byte[] certificate = new byte[serverResponse.Length - Encoding.UTF8.GetBytes("SERVER_HELLO").Length - sizeof(int)];
        Array.Copy(serverResponse, Encoding.UTF8.GetBytes("SERVER_HELLO").Length, certificate, 0, certificate.Length);
        _serverCertificate = new X509Certificate2(certificate);
        _randomServer = BitConverter.ToInt32(serverResponse, serverResponse.Length - sizeof(int));
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

    static byte[] GenerateRandomBytes(int length)
    {
        using RandomNumberGenerator rng = RandomNumberGenerator.Create();
        byte[] bytes = new byte[length];
        rng.GetBytes(bytes);
        return bytes;
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

    static byte[] EncryptPremasterSecret(byte[] premasterSecret)
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
