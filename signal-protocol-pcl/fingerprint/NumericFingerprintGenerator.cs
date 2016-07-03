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
 
using libsignal;
using libsignal.util;
using PCLCrypto;
using System;
using System.Diagnostics;
using System.Text;
using static PCLCrypto.WinRTCrypto;

namespace org.whispersystems.libsignal.fingerprint
{

    public class NumericFingerprintGenerator : FingerprintGenerator
    {

        private static readonly int VERSION = 0;

        private readonly long iterations;

        /**
         * Construct a fingerprint generator for 60 digit numerics.
         *
         * @param iterations The number of internal iterations to perform in the process of
         *                   generating a fingerprint. This needs to be constant, and synchronized
         *                   across all clients.
         *
         *                   The higher the iteration count, the higher the security level:
         *
         *                   - 1024 ~ 109.7 bits
         *                   - 1400 > 110 bits
         *                   - 5200 > 112 bits
         */
        public NumericFingerprintGenerator(long iterations)
        {
            this.iterations = iterations;
        }

        public object MessageDigest { get; private set; }

        /**
         * Generate a scannable and displayble fingerprint.
         *
         * @param localStableIdentifier The client's "stable" identifier.
         * @param localIdentityKey The client's identity key.
         * @param remoteStableIdentifier The remote party's "stable" identifier.
         * @param remoteIdentityKey The remote party's identity key.
         * @return A unique fingerprint for this conversation.
         */

        public Fingerprint createFor(string localStableIdentifier, IdentityKey localIdentityKey,
                               string remoteStableIdentifier, IdentityKey remoteIdentityKey)
        {
            DisplayableFingerprint displayableFingerprint = new DisplayableFingerprint(getDisplayStringFor(localStableIdentifier, localIdentityKey),
                                                                                       getDisplayStringFor(remoteStableIdentifier, remoteIdentityKey));

            ScannableFingerprint scannableFingerprint = new ScannableFingerprint(VERSION,
                                                                                 localStableIdentifier, localIdentityKey,
                                                                                 remoteStableIdentifier, remoteIdentityKey);

            return new Fingerprint(displayableFingerprint, scannableFingerprint);
        }

        private string getDisplayStringFor(string stableIdentifier, IdentityKey identityKey)
        {
            try
            {
                IHashAlgorithmProvider digest = HashAlgorithmProvider.OpenAlgorithm(PCLCrypto.HashAlgorithm.Sha512);

                byte[] publicKey = identityKey.getPublicKey().serialize();
                byte[] hash = ByteUtil.combine(ByteUtil.shortToByteArray(VERSION),
                                                           publicKey, Encoding.UTF8.GetBytes(stableIdentifier));

                for (int i = 0; i < iterations; i++)
                {
                    hash = digest.HashData(ByteUtil.combine(new byte[][] { hash, publicKey }));
                }

                return getEncodedChunk(hash, 0) +
                    getEncodedChunk(hash, 5) +
                    getEncodedChunk(hash, 10) +
                    getEncodedChunk(hash, 15) +
                    getEncodedChunk(hash, 20) +
                    getEncodedChunk(hash, 25);
            }
            catch (Exception e)
            {
                Debug.Assert(false, e.Message);
                throw e;
            }
        }

        private String getEncodedChunk(byte[] hash, int offset)
        {
            long chunk = ByteUtil.byteArray5ToLong(hash, offset) % 100000;
            return chunk.ToString().PadLeft(5, '0');
        }

    }

}