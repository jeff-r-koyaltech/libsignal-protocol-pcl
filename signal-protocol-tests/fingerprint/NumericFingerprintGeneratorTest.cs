/** 
 * Copyright (C) 2016 langboost
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
using Microsoft.VisualStudio.TestTools.UnitTesting;
using libsignal.ecc;
using libsignal;

namespace org.whispersystems.libsignal.fingerprint
{
    [TestClass]
    public class NumericFingerprintGeneratorTest
    {
        [TestMethod]
        public void testMatchingFingerprints()
        {
            ECKeyPair aliceKeyPair = Curve.generateKeyPair();
            ECKeyPair bobKeyPair = Curve.generateKeyPair();

            IdentityKey aliceIdentityKey = new IdentityKey(aliceKeyPair.getPublicKey());
            IdentityKey bobIdentityKey = new IdentityKey(bobKeyPair.getPublicKey());

            NumericFingerprintGenerator generator = new NumericFingerprintGenerator(1024);
            Fingerprint aliceFingerprint = generator.createFor("+14152222222", aliceIdentityKey,
                                                                               "+14153333333", bobIdentityKey);

            Fingerprint bobFingerprint = generator.createFor("+14153333333", bobIdentityKey,
                                                             "+14152222222", aliceIdentityKey);

            Assert.AreEqual<string>(aliceFingerprint.getDisplayableFingerprint().getDisplayText(),
                         bobFingerprint.getDisplayableFingerprint().getDisplayText());

            Assert.IsTrue(
                aliceFingerprint.getScannableFingerprint().compareTo(
                    bobFingerprint.getScannableFingerprint().getSerialized()));
            Assert.IsTrue(
                bobFingerprint.getScannableFingerprint().compareTo(
                    aliceFingerprint.getScannableFingerprint().getSerialized()));

            Assert.AreEqual<int>(aliceFingerprint.getDisplayableFingerprint().getDisplayText().Length, 60);
        }

        [TestMethod]
        public void testMismatchingFingerprints()
        {
            ECKeyPair aliceKeyPair = Curve.generateKeyPair();
            ECKeyPair bobKeyPair = Curve.generateKeyPair();
            ECKeyPair mitmKeyPair = Curve.generateKeyPair();

            IdentityKey aliceIdentityKey = new IdentityKey(aliceKeyPair.getPublicKey());
            IdentityKey bobIdentityKey = new IdentityKey(bobKeyPair.getPublicKey());
            IdentityKey mitmIdentityKey = new IdentityKey(mitmKeyPair.getPublicKey());

            NumericFingerprintGenerator generator = new NumericFingerprintGenerator(1024);
            Fingerprint aliceFingerprint = generator.createFor("+14152222222", aliceIdentityKey,
                                                                               "+14153333333", mitmIdentityKey);

            Fingerprint bobFingerprint = generator.createFor("+14153333333", bobIdentityKey,
                                                             "+14152222222", aliceIdentityKey);

            Assert.AreNotEqual<string>(aliceFingerprint.getDisplayableFingerprint().getDisplayText(),
                          bobFingerprint.getDisplayableFingerprint().getDisplayText());

            Assert.IsFalse(aliceFingerprint.getScannableFingerprint().compareTo(bobFingerprint.getScannableFingerprint().getSerialized()));
            Assert.IsFalse(bobFingerprint.getScannableFingerprint().compareTo(aliceFingerprint.getScannableFingerprint().getSerialized()));
        }

        [TestMethod]
        public void testMismatchingIdentifiers()
        {
            ECKeyPair aliceKeyPair = Curve.generateKeyPair();
            ECKeyPair bobKeyPair = Curve.generateKeyPair();

            IdentityKey aliceIdentityKey = new IdentityKey(aliceKeyPair.getPublicKey());
            IdentityKey bobIdentityKey = new IdentityKey(bobKeyPair.getPublicKey());

            NumericFingerprintGenerator generator = new NumericFingerprintGenerator(1024);
            Fingerprint aliceFingerprint = generator.createFor("+141512222222", aliceIdentityKey,
                                                                               "+14153333333", bobIdentityKey);

            Fingerprint bobFingerprint = generator.createFor("+14153333333", bobIdentityKey,
                                                             "+14152222222", aliceIdentityKey);

            Assert.AreNotEqual<string>(aliceFingerprint.getDisplayableFingerprint().getDisplayText(),
                          bobFingerprint.getDisplayableFingerprint().getDisplayText());

            try
            {
                ;
                aliceFingerprint.getScannableFingerprint().compareTo(bobFingerprint.getScannableFingerprint().getSerialized());
                throw new Exception("Should mismatch!");
            }
            catch (FingerprintIdentifierMismatchException)
            {
                // good
            }

            try
            {
                bobFingerprint.getScannableFingerprint().compareTo(aliceFingerprint.getScannableFingerprint().getSerialized());
                throw new Exception("Should mismatch!");
            }
            catch (FingerprintIdentifierMismatchException)
            {
                // good
            }
        }

    }
}