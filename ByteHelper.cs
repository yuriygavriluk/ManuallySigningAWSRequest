using System.Globalization;
using System.Text;

namespace ManuallySigningAWSRequest
{
    public static class ByteHelper
    {
        public static string ToHex(this byte[] data)
        {
            StringBuilder stringBuilder = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                stringBuilder.Append(data[i].ToString("x2", CultureInfo.InvariantCulture));
            }

            return stringBuilder.ToString();
        }
    }
}
