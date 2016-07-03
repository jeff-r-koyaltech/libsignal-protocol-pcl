/** 
 * Copyright (C) 2016 smndtrl, langboost
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
using libsignal;
using libsignal.util;
using System.Text;
using static libsignal.fingerprint.FingerprintProtos;

namespace org.whispersystems.libsignal.fingerprint
{

    public class ScannableFingerprint
    {

        private readonly CombinedFingerprint combinedFingerprint;

        public ScannableFingerprint(int version,
                                    string localStableIdentifier, IdentityKey localIdentityKey,
                                    string remoteStableIdentifier, IdentityKey remoteIdentityKey)
        {
            this.combinedFingerprint = CombinedFingerprint.CreateBuilder()
                                                          .SetVersion((uint)version)
                                                          .SetLocalFingerprint(FingerprintData.CreateBuilder()
                                                                                              .SetIdentifier(ByteString.CopyFrom(Encoding.UTF8.GetBytes(localStableIdentifier)))
                                                                                              .SetPublicKey(ByteString.CopyFrom(localIdentityKey.serialize())))
                                                          .SetRemoteFingerprint(FingerprintData.CreateBuilder()
                                                                                               .SetIdentifier(ByteString.CopyFrom(Encoding.UTF8.GetBytes(remoteStableIdentifier)))
                                                                                               .SetPublicKey(ByteString.CopyFrom(remoteIdentityKey.serialize())))
                                                          .Build();
        }

        /**
         * @return A byte string to be displayed in a QR code.
         */
        public byte[] getSerialized()
        {
            return combinedFingerprint.ToByteArray();
        }

        /**
         * Compare a scanned QR code with what we expect.
         *
         * @param scannedFingerprintData The scanned data
         * @return True if matching, otehrwise false.
         * @throws FingerprintVersionMismatchException if the scanned fingerprint is the wrong version.
         * @throws FingerprintIdentifierMismatchException if the scanned fingerprint is for the wrong stable identifier.
         */
        public bool compareTo(byte[] scannedFingerprintData)
        /* throws FingerprintVersionMismatchException,
               FingerprintIdentifierMismatchException,
               FingerprintParsingException */
        {
            try
            {
                CombinedFingerprint scannedFingerprint = CombinedFingerprint.ParseFrom(scannedFingerprintData);

                if (!scannedFingerprint.HasRemoteFingerprint || !scannedFingerprint.HasLocalFingerprint ||
                    !scannedFingerprint.HasVersion || scannedFingerprint.Version != combinedFingerprint.Version)
                {
                    throw new FingerprintVersionMismatchException();
                }

                if (!combinedFingerprint.LocalFingerprint.Identifier.Equals(scannedFingerprint.RemoteFingerprint.Identifier) ||
                    !combinedFingerprint.RemoteFingerprint.Identifier.Equals(scannedFingerprint.LocalFingerprint.Identifier))
                {
                    throw new FingerprintIdentifierMismatchException(combinedFingerprint.LocalFingerprint.Identifier.ToStringUtf8(),
                                                                     combinedFingerprint.RemoteFingerprint.Identifier.ToStringUtf8(),
                                                                     scannedFingerprint.LocalFingerprint.Identifier.ToStringUtf8(),
                                                                     scannedFingerprint.RemoteFingerprint.Identifier.ToStringUtf8());
                }

                return ByteUtil.isEqual(combinedFingerprint.LocalFingerprint.ToByteArray(), scannedFingerprint.RemoteFingerprint.ToByteArray()) &&
                       ByteUtil.isEqual(combinedFingerprint.RemoteFingerprint.ToByteArray(), scannedFingerprint.LocalFingerprint.ToByteArray());
            }
            catch (InvalidProtocolBufferException e)
            {
                throw new FingerprintParsingException(e);
            }
        }
    }
}