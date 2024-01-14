using System.Security.Cryptography;

namespace TlsModel.Library.Helpers;

public static class RandomHelper
{
    public static int GenerateRandomPrime(int min, int max)
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

    public static bool IsPrime(int number)
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

    public static byte[] GenerateRandomBytes(int length)
    {
        using RandomNumberGenerator rng = RandomNumberGenerator.Create();
        byte[] bytes = new byte[length];
        rng.GetBytes(bytes);
        return bytes;
    }
}
