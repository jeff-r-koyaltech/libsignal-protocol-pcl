using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TextSecure.libaxolotl
{
    class InvalidMacException : Exception
    {

        public InvalidMacException(String detailMessage)
            :base(detailMessage)
        {
        }

        public InvalidMacException(Exception exception)
            :base(exception.Message)
        {

        }
    }
}
