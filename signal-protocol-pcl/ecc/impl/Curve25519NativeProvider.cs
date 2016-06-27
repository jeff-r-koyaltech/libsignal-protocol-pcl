/** 
 * Copyright (C) 2015 langboost
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

namespace libaxolotl.ecc.impl
{
	class Curve25519NativeProvider : ICurve25519Provider
	{
		private curve25519.Curve25519Native native = new curve25519.Curve25519Native();

		public byte[] calculateAgreement(byte[] ourPrivate, byte[] theirPublic)
		{
			return native.calculateAgreement(ourPrivate, theirPublic);
		}

		public byte[] calculateSignature(byte[] random, byte[] privateKey, byte[] message)
		{
			return native.calculateSignature(random, privateKey, message);
		}

		public byte[] generatePrivateKey(byte[] random)
		{
			return native.generatePrivateKey(random);
		}

		public byte[] generatePublicKey(byte[] privateKey)
		{
			return native.generatePublicKey(privateKey);
		}

		public bool isNative()
		{
			return native.isNative();
		}

		public bool verifySignature(byte[] publicKey, byte[] message, byte[] signature)
		{
			return native.verifySignature(publicKey, message, signature);
		}
	}
}
