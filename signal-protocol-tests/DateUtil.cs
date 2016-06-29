using System;

namespace libaxolotl_test
{
    class DateUtil
    {
        private static readonly DateTime Jan1st1970 = new DateTime
            (1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static ulong currentTimeMillis()
        {
            return (ulong)(DateTime.UtcNow - Jan1st1970).TotalMilliseconds;
        }
    }
}
