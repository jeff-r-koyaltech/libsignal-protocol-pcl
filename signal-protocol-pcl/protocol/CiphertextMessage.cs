/** 
 * Copyright (C) 2015 smndtrl
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libaxolotl.protocol
{
    public abstract class CiphertextMessage // interface
    {

        public const uint UNSUPPORTED_VERSION = 1;
        public const uint CURRENT_VERSION = 3;

        public const uint WHISPER_TYPE = 2;
        public const uint PREKEY_TYPE = 3;
        public const uint SENDERKEY_TYPE = 4;
        public const uint SENDERKEY_DISTRIBUTION_TYPE = 5;

        // This should be the worst case (worse than V2).  So not always accurate, but good enough for padding.
        public const uint ENCRYPTED_MESSAGE_OVERHEAD = 53;

        public abstract byte[] serialize(); // -abstract
        public abstract uint getType(); // -abstract

    }
}
