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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static libaxolotl.state.StorageProtos;

namespace libaxolotl.state
{
    public class SignedPreKeyRecord
    {

        private SignedPreKeyRecordStructure structure;

        public SignedPreKeyRecord(uint id, ulong timestamp, ECKeyPair keyPair, byte[] signature)
        {
            this.structure = SignedPreKeyRecordStructure.CreateBuilder()
                                                        .SetId(id)
                                                        .SetPublicKey(ByteString.CopyFrom(keyPair.getPublicKey()
                                                                                                 .serialize()))
                                                        .SetPrivateKey(ByteString.CopyFrom(keyPair.getPrivateKey()
                                                                                                  .serialize()))
                                                        .SetSignature(ByteString.CopyFrom(signature))
                                                        .SetTimestamp(timestamp)
                                                        .Build();
        }

        public SignedPreKeyRecord(byte[] serialized)
        {
            this.structure = SignedPreKeyRecordStructure.ParseFrom(serialized);
        }

        public uint getId()
        {
            return this.structure.Id;
        }

        public ulong getTimestamp()
        {
            return this.structure.Timestamp;
        }

        public ECKeyPair getKeyPair()
        {
            try
            {
                ECPublicKey publicKey = Curve.decodePoint(this.structure.PublicKey.ToByteArray(), 0);
                ECPrivateKey privateKey = Curve.decodePrivatePoint(this.structure.PrivateKey.ToByteArray());

                return new ECKeyPair(publicKey, privateKey);
            }
            catch (InvalidKeyException e)
            {
                throw new Exception(e.Message);
            }
        }

        public byte[] getSignature()
        {
            return this.structure.Signature.ToByteArray();
        }

        public byte[] serialize()
        {
            return this.structure.ToByteArray();
        }
    }
}
