using System.Security.Cryptography;
using System.Text;

namespace TlsModel.Library.Helpers;

public class CryptoHelper
{
    public static byte[] GenerateSessionKey(byte[] premasterSecret, int randomServer, int randomClient)
    {
        byte[] inputKeyingMaterial = Concatenate(
            premasterSecret,
            BitConverter.GetBytes(randomServer),
            BitConverter.GetBytes(randomClient));

        using var hmac = new HMACSHA256();
        byte[] sessionKey = HKDF(inputKeyingMaterial, 48, hmac);
        return sessionKey;
    }

    public static byte[] Concatenate(params byte[][] arrays)
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

    public static byte[] HKDF(byte[] ikm, int length, HMAC hmac)
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

    public static byte[] EncryptAes(byte[] data, byte[] key)
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

    public static byte[] DecryptAes(byte[] encryptedData, byte[] key)
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
