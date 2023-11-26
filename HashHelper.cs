using System.Security.Cryptography;
using System.Text;

namespace ManuallySigningAWSRequest
{
    public static class HashHelper
    {
        public static byte[] ToSha256(this string input)
        {
            var hashier = SHA256.Create();
            var inputBytes = Encoding.UTF8.GetBytes(input);

            return hashier.ComputeHash(inputBytes);
        }

        public static byte[] HMACSign(this byte[] data, byte[] key)
        {
            using (KeyedHashAlgorithm keyedHashAlgorithm = new HMACSHA256())
            {
                keyedHashAlgorithm.Key = key;
                var result = keyedHashAlgorithm.ComputeHash(data);

                return result;
            }
        }

        public static byte[] HMACSign(this byte[] data, string key)
        {
            return HMACSign(data, Encoding.UTF8.GetBytes(key));
        }

        public static byte[] HMACSign(this string data, byte[] key)
        {
            return HMACSign(Encoding.UTF8.GetBytes(data), key);
        }

        public static byte[] HMACSign(this string data, string key)
        {
            return HMACSign(Encoding.UTF8.GetBytes(data), Encoding.UTF8.GetBytes(key));
        }

        public static byte[] HMACSign(this string data, char[] key)
        {
            return HMACSign(Encoding.UTF8.GetBytes(data), Encoding.UTF8.GetBytes(key));
        }
    }
}
