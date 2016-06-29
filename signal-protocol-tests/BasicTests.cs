using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using libaxolotl.ecc;
using System.Collections;
using org.whispersystems.curve25519;

namespace libaxolotl_test
{
	[TestClass]
	public class BasicTests
	{
		/// <summary>
		/// It's important that we test byte [] for equality by value.
		/// </summary>
		[TestMethod]
		public void TestECPublicKeyEquals()
		{
            //curve25519.Curve25519Native native = new curve25519.Curve25519Native();
            Curve25519 native = Curve25519.getInstance(Curve25519.BEST);
			byte[] privKey = native.generatePrivateKey();
			byte[] pubKey = native.generatePublicKey(privKey);
			DjbECPublicKey key1 = new DjbECPublicKey(pubKey);

			byte[] pubKey2 = native.generatePublicKey(privKey);

			Assert.IsTrue(StructuralComparisons.StructuralEqualityComparer.Equals(
					pubKey, pubKey2));

			DjbECPublicKey key2 = new DjbECPublicKey(pubKey2);

			Assert.IsTrue(key1.Equals(key2));

			int hash1 = key1.GetHashCode();
			int hash2 = key2.GetHashCode();

			Assert.AreEqual<int>(hash1, hash2);
		}
	}
}
