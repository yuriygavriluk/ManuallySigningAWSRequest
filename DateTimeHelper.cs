using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ManuallySigningAWSRequest
{
    public static class DateTimeHelper
    {
        public static string FormatDateTime(this DateTime dateTime, string formatString)
        {
            return dateTime.ToUniversalTime().ToString(formatString, CultureInfo.InvariantCulture); 
        }
    }
}
