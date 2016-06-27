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

using Google.ProtocolBuffers;
using libaxolotl.ecc;
using libaxolotl.util;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libaxolotl.protocol
{
    public class KeyExchangeMessage
    {

        public static readonly uint INITIATE_FLAG = 0x01;
        public static readonly uint RESPONSE_FLAG = 0X02;
        public static readonly uint SIMULTAENOUS_INITIATE_FLAG = 0x04;

        private readonly uint version;
        private readonly uint supportedVersion;
        private readonly uint sequence;
        private readonly uint flags;

        private readonly ECPublicKey baseKey;
        private readonly byte[] baseKeySignature;
        private readonly ECPublicKey ratchetKey;
        private readonly IdentityKey identityKey;
        private readonly byte[] serialized;

        public KeyExchangeMessage(uint messageVersion, uint sequence, uint flags,
                                  ECPublicKey baseKey, byte[] baseKeySignature,
                                  ECPublicKey ratchetKey,
                                  IdentityKey identityKey)
        {
            this.supportedVersion = CiphertextMessage.CURRENT_VERSION;
            this.version = messageVersion;
            this.sequence = sequence;
            this.flags = flags;
            this.baseKey = baseKey;
            this.baseKeySignature = baseKeySignature;
            this.ratchetKey = ratchetKey;
            this.identityKey = identityKey;

            byte[] version = { ByteUtil.intsToByteHighAndLow((int)this.version, (int)this.supportedVersion) };
            WhisperProtos.KeyExchangeMessage.Builder builder = WhisperProtos.KeyExchangeMessage
                                           .CreateBuilder()
                                           .SetId((sequence << 5) | flags) //(sequence << 5) | flags
                                           .SetBaseKey(ByteString.CopyFrom(baseKey.serialize()))
                                           .SetRatchetKey(ByteString.CopyFrom(ratchetKey.serialize()))
                                           .SetIdentityKey(ByteString.CopyFrom(identityKey.serialize()));

            if (messageVersion >= 3)
            {
                builder.SetBaseKeySignature(ByteString.CopyFrom(baseKeySignature));
            }

            this.serialized = ByteUtil.combine(version, builder.Build().ToByteArray());
        }

        public KeyExchangeMessage(byte[] serialized)
        {
            try
            {
                byte[][] parts = ByteUtil.split(serialized, 1, serialized.Length - 1);
                this.version = (uint)ByteUtil.highBitsToInt(parts[0][0]);
                this.supportedVersion = (uint)ByteUtil.lowBitsToInt(parts[0][0]);

                if (this.version <= CiphertextMessage.UNSUPPORTED_VERSION)
                {
                    throw new LegacyMessageException("Unsupported legacy version: " + this.version);
                }

                if (this.version > CiphertextMessage.CURRENT_VERSION)
                {
                    throw new InvalidVersionException("Unknown version: " + this.version);
                }

                WhisperProtos.KeyExchangeMessage message = WhisperProtos.KeyExchangeMessage.ParseFrom(parts[1]);

                if (!message.HasId || !message.HasBaseKey ||
                    !message.HasRatchetKey || !message.HasIdentityKey ||
                    (this.version >= 3 && !message.HasBaseKeySignature))
                {
                    throw new InvalidMessageException("Some required fields missing!");
                }

                this.sequence = message.Id >> 5;
                this.flags = message.Id & 0x1f;
                this.serialized = serialized;
                this.baseKey = Curve.decodePoint(message.BaseKey.ToByteArray(), 0);
                this.baseKeySignature = message.BaseKeySignature.ToByteArray();
                this.ratchetKey = Curve.decodePoint(message.RatchetKey.ToByteArray(), 0);
                this.identityKey = new IdentityKey(message.IdentityKey.ToByteArray(), 0);
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidMessageException(e);
            }
        }

        public uint getVersion()
        {
            return version;
        }

        public ECPublicKey getBaseKey()
        {
            return baseKey;
        }

        public byte[] getBaseKeySignature()
        {
            return baseKeySignature;
        }

        public ECPublicKey getRatchetKey()
        {
            return ratchetKey;
        }

        public IdentityKey getIdentityKey()
        {
            return identityKey;
        }

        public bool hasIdentityKey()
        {
            return true;
        }

        public uint getMaxVersion()
        {
            return supportedVersion;
        }

        public bool isResponse()
        {
            return ((flags & RESPONSE_FLAG) != 0);
        }

        public bool isInitiate()
        {
            return (flags & INITIATE_FLAG) != 0;
        }

        public bool isResponseForSimultaneousInitiate()
        {
            return (flags & SIMULTAENOUS_INITIATE_FLAG) != 0;
        }

        public uint getFlags()
        {
            return flags;
        }

        public uint getSequence()
        {
            return sequence;
        }

        public byte[] serialize()
        {
            return serialized;
        }
    }
}
