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
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace libaxolotl.util
{
    public class Sign
    {
        public static byte[] sha256sum(byte[] key, byte[] message)
        {
            MacAlgorithmProvider provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha256);

            IBuffer buffKey = CryptographicBuffer.CreateFromByteArray(key);
            CryptographicKey hmacKey = provider.CreateKey(buffKey);

            IBuffer buffMessage = CryptographicBuffer.CreateFromByteArray(message);

            IBuffer buffHMAC = CryptographicEngine.Sign(hmacKey, buffMessage);

            byte[] hmac;

            CryptographicBuffer.CopyToByteArray(buffHMAC, out hmac);

            return hmac;
        }
    }

    public class Sha256
    {
        public static byte[] Sign(byte[] key, byte[] message)
        {
            MacAlgorithmProvider provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha256);

            IBuffer buffKey = CryptographicBuffer.CreateFromByteArray(key);
            CryptographicKey hmacKey = provider.CreateKey(buffKey);

            IBuffer buffMessage = CryptographicBuffer.CreateFromByteArray(message);

            IBuffer buffHMAC = CryptographicEngine.Sign(hmacKey, buffMessage);

            byte[] hmac;

            CryptographicBuffer.CopyToByteArray(buffHMAC, out hmac);

            return hmac;
        }

        public static bool Verify(byte[] key, byte[] message, byte[] signature)
        {
            MacAlgorithmProvider provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha256);

            IBuffer buffKey = CryptographicBuffer.CreateFromByteArray(key);
            CryptographicKey hmacKey = provider.CreateKey(buffKey);

            IBuffer buffMessage = CryptographicBuffer.CreateFromByteArray(message);

            IBuffer buffSignature = CryptographicBuffer.CreateFromByteArray(signature);

            return CryptographicEngine.VerifySignature(hmacKey, buffMessage, buffSignature);
        }
    }

    public class Encrypt
    {
        public static byte[] aesCbcPkcs5(byte[] message, byte[] key, byte[] iv)
        {
            SymmetricKeyAlgorithmProvider objAlg = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7); // PKCS5
            IBuffer buffKey = CryptographicBuffer.CreateFromByteArray(key);
            CryptographicKey ckey = objAlg.CreateSymmetricKey(buffKey);


            IBuffer buffPlaintext = CryptographicBuffer.CreateFromByteArray(message);
            IBuffer buffIV = CryptographicBuffer.CreateFromByteArray(iv);
            IBuffer buffEncrypt = CryptographicEngine.Encrypt(ckey, buffPlaintext, buffIV);

            byte[] ret;
            CryptographicBuffer.CopyToByteArray(buffEncrypt, out ret);

            return ret;
        }
        public static byte[] aesCtr(byte[] message, byte[] key, uint counter)
        {
            SymmetricKeyAlgorithmProvider objAlg = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7); // CRT
            IBuffer buffKey = CryptographicBuffer.CreateFromByteArray(key);
            CryptographicKey ckey = objAlg.CreateSymmetricKey(buffKey);

            byte[] ivBytes = new byte[16];
            ByteUtil.intToByteArray(ivBytes, 0, (int)counter);

            IBuffer buffPlaintext = CryptographicBuffer.CreateFromByteArray(message);
            IBuffer buffIV = CryptographicBuffer.CreateFromByteArray(ivBytes);
            IBuffer buffEncrypt = CryptographicEngine.Encrypt(ckey, buffPlaintext, buffIV);

            byte[] ret;
            CryptographicBuffer.CopyToByteArray(buffEncrypt, out ret);

            return ret;
        }


    }

    public class Decrypt
    {
        public static byte[] aesCbcPkcs5(byte[] message, byte[] key, byte[] iv)
        {
            SymmetricKeyAlgorithmProvider objAlg = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
            IBuffer buffKey = CryptographicBuffer.CreateFromByteArray(key);
            CryptographicKey ckey = objAlg.CreateSymmetricKey(buffKey);

            if (message.Length % objAlg.BlockLength != 0) throw new Exception("Invalid ciphertext length");


            IBuffer buffPlaintext = CryptographicBuffer.CreateFromByteArray(message);
            IBuffer buffIV = CryptographicBuffer.CreateFromByteArray(iv);
            IBuffer buffEncrypt = CryptographicEngine.Decrypt(ckey, buffPlaintext, buffIV);

            byte[] ret;
            CryptographicBuffer.CopyToByteArray(buffEncrypt, out ret);
            return ret;
        }

        public static byte[] aesCtr(byte[] message, byte[] key, uint counter)
        {
            SymmetricKeyAlgorithmProvider objAlg = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
            IBuffer buffKey = CryptographicBuffer.CreateFromByteArray(key);
            CryptographicKey ckey = objAlg.CreateSymmetricKey(buffKey);

            byte[] ivBytes = new byte[16];
            ByteUtil.intToByteArray(ivBytes, 0, (int)counter);

            IBuffer buffPlaintext = CryptographicBuffer.CreateFromByteArray(message);
            IBuffer buffIV = CryptographicBuffer.CreateFromByteArray(ivBytes);
            IBuffer buffEncrypt = CryptographicEngine.Decrypt(ckey, buffPlaintext, buffIV);

            byte[] ret;
            CryptographicBuffer.CopyToByteArray(buffEncrypt, out ret);
            return ret;
        }
    }

    public static class CryptoHelper
    {
        public static void Shuffle<T>(this IList<T> list)
        {
            Random rng = new Random();
            int n = list.Count;
            while (n > 1)
            {
                n--;
                int k = rng.Next(n + 1);
                T value = list[k];
                list[k] = list[n];
                list[n] = value;
            }
        }
    }
}
