using libaxolotl;
using libaxolotl.ecc;
using libaxolotl.exceptions;
using libaxolotl.protocol;
using libaxolotl.state;
using libaxolotl.util;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace libaxolotl_test
{

    [TestClass]
    public class SessionBuilderTest
    {
        private static readonly AxolotlAddress ALICE_ADDRESS = new AxolotlAddress("+14151111111", 1);
        private static readonly AxolotlAddress BOB_ADDRESS = new AxolotlAddress("+14152222222", 1);

        class BobDecryptionCallback : DecryptionCallback
        {
            readonly AxolotlStore bobStore;
            readonly String originalMessage;

            public BobDecryptionCallback(AxolotlStore bobStore, String originalMessage)
            {
                this.bobStore = bobStore;
                this.originalMessage = originalMessage;
            }

            public void handlePlaintext(byte[] plaintext)
            {
                Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));
                Assert.IsFalse(bobStore.ContainsSession(ALICE_ADDRESS));
            }
        }

        [TestMethod, TestCategory("libaxolotl")]
        public void testBasicPreKeyV2()
        {
            AxolotlStore aliceStore = new TestInMemoryAxolotlStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

            AxolotlStore bobStore = new TestInMemoryAxolotlStore();
            ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
            PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(), 1,
                                                          31337, bobPreKeyPair.getPublicKey(),
                                                          0, null, null,
                                                          bobStore.GetIdentityKeyPair().getPublicKey());

            aliceSessionBuilder.process(bobPreKey);

            Assert.IsTrue(aliceStore.ContainsSession(BOB_ADDRESS));
            Assert.AreEqual((uint)2, aliceStore.LoadSession(BOB_ADDRESS).getSessionState().getSessionVersion());

            String originalMessage = "L'homme est condamné à être libre";
            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            CiphertextMessage outgoingMessage = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, outgoingMessage.getType());

            PreKeyWhisperMessage incomingMessage = new PreKeyWhisperMessage(outgoingMessage.serialize());
            bobStore.StorePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));

            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
            byte[] plaintext = bobSessionCipher.decrypt(incomingMessage);

            Assert.IsTrue(bobStore.ContainsSession(ALICE_ADDRESS));
            Assert.AreEqual((uint)2, bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getSessionVersion());
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));
            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, bobOutgoingMessage.getType());

            byte[] alicePlaintext = aliceSessionCipher.decrypt((WhisperMessage)bobOutgoingMessage);
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(alicePlaintext));

            runInteraction(aliceStore, bobStore);

            aliceStore = new TestInMemoryAxolotlStore();
            aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);

            bobPreKeyPair = Curve.generateKeyPair();
            bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(),
                                         1, 31338, bobPreKeyPair.getPublicKey(),
                                         0, null, null, bobStore.GetIdentityKeyPair().getPublicKey());

            bobStore.StorePreKey(31338, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
            aliceSessionBuilder.process(bobPreKey);

            outgoingMessage = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            try
            {
                bobSessionCipher.decrypt(new PreKeyWhisperMessage(outgoingMessage.serialize()));
                throw new Exception("shouldn't be trusted!");
            }
            catch (UntrustedIdentityException uie)
            {
                bobStore.SaveIdentity(ALICE_ADDRESS.getName(), new PreKeyWhisperMessage(outgoingMessage.serialize()).getIdentityKey());
            }

            plaintext = bobSessionCipher.decrypt(new PreKeyWhisperMessage(outgoingMessage.serialize()));

            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(), 1,
                                         31337, Curve.generateKeyPair().getPublicKey(),
                                         0, null, null,
                                         aliceStore.GetIdentityKeyPair().getPublicKey());

            try
            {
                aliceSessionBuilder.process(bobPreKey);
                throw new Exception("shoulnd't be trusted!");
            }
            catch (UntrustedIdentityException uie)
            {
                // good
            }
        }

        [TestMethod, TestCategory("libaxolotl")]
        public void testBasicPreKeyV3()
        {
            AxolotlStore aliceStore = new TestInMemoryAxolotlStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

            AxolotlStore bobStore = new TestInMemoryAxolotlStore();
            ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
            ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
            byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.GetIdentityKeyPair().getPrivateKey(),
                                                                             bobSignedPreKeyPair.getPublicKey().serialize());

            PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(), 1,
                                                      31337, bobPreKeyPair.getPublicKey(),
                                                      22, bobSignedPreKeyPair.getPublicKey(),
                                                      bobSignedPreKeySignature,
                                                      bobStore.GetIdentityKeyPair().getPublicKey());

            aliceSessionBuilder.process(bobPreKey);

            Assert.IsTrue(aliceStore.ContainsSession(BOB_ADDRESS));
            Assert.AreEqual((uint)3, aliceStore.LoadSession(BOB_ADDRESS).getSessionState().getSessionVersion());

            String originalMessage = "L'homme est condamné à être libre";
            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            CiphertextMessage outgoingMessage = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, outgoingMessage.getType());

            PreKeyWhisperMessage incomingMessage = new PreKeyWhisperMessage(outgoingMessage.serialize());
            bobStore.StorePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
            bobStore.StoreSignedPreKey(22, new SignedPreKeyRecord(22, DateUtil.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
            byte[] plaintext = bobSessionCipher.decrypt(incomingMessage, new BobDecryptionCallback(bobStore, originalMessage));

            Assert.IsTrue(bobStore.ContainsSession(ALICE_ADDRESS));
            Assert.AreEqual((uint)3, bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getSessionVersion());
            Assert.IsNotNull(bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getAliceBaseKey());
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));
            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, bobOutgoingMessage.getType());

            byte[] alicePlaintext = aliceSessionCipher.decrypt(new WhisperMessage(bobOutgoingMessage.serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(alicePlaintext));

            runInteraction(aliceStore, bobStore);

            aliceStore = new TestInMemoryAxolotlStore();
            aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);

            bobPreKeyPair = Curve.generateKeyPair();
            bobSignedPreKeyPair = Curve.generateKeyPair();
            bobSignedPreKeySignature = Curve.calculateSignature(bobStore.GetIdentityKeyPair().getPrivateKey(), bobSignedPreKeyPair.getPublicKey().serialize());
            bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(),
                                         1, 31338, bobPreKeyPair.getPublicKey(),
                                         23, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                                         bobStore.GetIdentityKeyPair().getPublicKey());

            bobStore.StorePreKey(31338, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
            bobStore.StoreSignedPreKey(23, new SignedPreKeyRecord(23, DateUtil.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));
            aliceSessionBuilder.process(bobPreKey);

            outgoingMessage = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            try
            {
                plaintext = bobSessionCipher.decrypt(new PreKeyWhisperMessage(outgoingMessage.serialize()));
                throw new Exception("shouldn't be trusted!");
            }
            catch (UntrustedIdentityException uie)
            {
                bobStore.SaveIdentity(ALICE_ADDRESS.getName(), new PreKeyWhisperMessage(outgoingMessage.serialize()).getIdentityKey());
            }

            plaintext = bobSessionCipher.decrypt(new PreKeyWhisperMessage(outgoingMessage.serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(), 1,
                                         31337, Curve.generateKeyPair().getPublicKey(),
                                         23, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                                         aliceStore.GetIdentityKeyPair().getPublicKey());

            try
            {
                aliceSessionBuilder.process(bobPreKey);
                throw new Exception("shoulnd't be trusted!");
            }
            catch (UntrustedIdentityException uie)
            {
                // good
            }
        }

        [TestMethod, TestCategory("libaxolotl")]
        public void testBadSignedPreKeySignature()
        {
            AxolotlStore aliceStore = new TestInMemoryAxolotlStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

            IdentityKeyStore bobIdentityKeyStore = new TestInMemoryIdentityKeyStore();

            ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
            ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
            byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobIdentityKeyStore.GetIdentityKeyPair().getPrivateKey(),
                                                                          bobSignedPreKeyPair.getPublicKey().serialize());


            for (int i = 0; i < bobSignedPreKeySignature.Length * 8; i++)
            {
                byte[] modifiedSignature = new byte[bobSignedPreKeySignature.Length];
                Array.Copy(bobSignedPreKeySignature, 0, modifiedSignature, 0, modifiedSignature.Length);

                modifiedSignature[i / 8] ^= (byte)(0x01 << (i % 8));

                PreKeyBundle bobPreKey = new PreKeyBundle(bobIdentityKeyStore.GetLocalRegistrationId(), 1,
                                                          31337, bobPreKeyPair.getPublicKey(),
                                                          22, bobSignedPreKeyPair.getPublicKey(), modifiedSignature,
                                                          bobIdentityKeyStore.GetIdentityKeyPair().getPublicKey());
                
                try
                {
                    aliceSessionBuilder.process(bobPreKey);
                    throw new Exception("Accepted modified device key signature!");
                }
                catch (InvalidKeyException ike)
                {
                    // good
                }
            }

            PreKeyBundle bobPreKey2 = new PreKeyBundle(bobIdentityKeyStore.GetLocalRegistrationId(), 1,
                                                      31337, bobPreKeyPair.getPublicKey(),
                                                      22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                                                      bobIdentityKeyStore.GetIdentityKeyPair().getPublicKey());

            aliceSessionBuilder.process(bobPreKey2);
        }

        [TestMethod, TestCategory("libaxolotl")]
        public void testRepeatBundleMessageV2()
        {
            AxolotlStore aliceStore = new TestInMemoryAxolotlStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

            AxolotlStore bobStore = new TestInMemoryAxolotlStore();

            ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
            ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
            byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.GetIdentityKeyPair().getPrivateKey(),
                                                                          bobSignedPreKeyPair.getPublicKey().serialize());

            PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(), 1,
                                                      31337, bobPreKeyPair.getPublicKey(),
                                                      0, null, null,
                                                      bobStore.GetIdentityKeyPair().getPublicKey());

            bobStore.StorePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
            bobStore.StoreSignedPreKey(22, new SignedPreKeyRecord(22, DateUtil.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

            aliceSessionBuilder.process(bobPreKey);

            String originalMessage = "L'homme est condamné à être libre";
            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));
            CiphertextMessage outgoingMessageTwo = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, outgoingMessageOne.getType());

            PreKeyWhisperMessage incomingMessage = new PreKeyWhisperMessage(outgoingMessageOne.serialize());

            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            byte[] plaintext = bobSessionCipher.decrypt(incomingMessage);
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            byte[] alicePlaintext = aliceSessionCipher.decrypt(new WhisperMessage(bobOutgoingMessage.serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(alicePlaintext));

            // The test

            PreKeyWhisperMessage incomingMessageTwo = new PreKeyWhisperMessage(outgoingMessageTwo.serialize());

            plaintext = bobSessionCipher.decrypt(incomingMessageTwo);
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            bobOutgoingMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));
            alicePlaintext = aliceSessionCipher.decrypt(new WhisperMessage(bobOutgoingMessage.serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(alicePlaintext));

        }

        [TestMethod, TestCategory("libaxolotl")]
        public void testRepeatBundleMessageV3()
        {
            AxolotlStore aliceStore = new TestInMemoryAxolotlStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

            AxolotlStore bobStore = new TestInMemoryAxolotlStore();

            ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
            ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
            byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.GetIdentityKeyPair().getPrivateKey(),
                                                                          bobSignedPreKeyPair.getPublicKey().serialize());

            PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(), 1,
                                                      31337, bobPreKeyPair.getPublicKey(),
                                                      22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                                                      bobStore.GetIdentityKeyPair().getPublicKey());

            bobStore.StorePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
            bobStore.StoreSignedPreKey(22, new SignedPreKeyRecord(22, DateUtil.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

            aliceSessionBuilder.process(bobPreKey);

            String originalMessage = "L'homme est condamné à être libre";
            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));
            CiphertextMessage outgoingMessageTwo = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, outgoingMessageOne.getType());
            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, outgoingMessageTwo.getType());

            PreKeyWhisperMessage incomingMessage = new PreKeyWhisperMessage(outgoingMessageOne.serialize());

            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            byte[] plaintext = bobSessionCipher.decrypt(incomingMessage);
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            byte[] alicePlaintext = aliceSessionCipher.decrypt(new WhisperMessage(bobOutgoingMessage.serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(alicePlaintext));

            // The test

            PreKeyWhisperMessage incomingMessageTwo = new PreKeyWhisperMessage(outgoingMessageTwo.serialize());

            plaintext = bobSessionCipher.decrypt(new PreKeyWhisperMessage(incomingMessageTwo.serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            bobOutgoingMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));
            alicePlaintext = aliceSessionCipher.decrypt(new WhisperMessage(bobOutgoingMessage.serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(alicePlaintext));

        }

        [TestMethod, TestCategory("libaxolotl")]
        public void testBadMessageBundle()
        {
            AxolotlStore aliceStore = new TestInMemoryAxolotlStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

            AxolotlStore bobStore = new TestInMemoryAxolotlStore();

            ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
            ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
            byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.GetIdentityKeyPair().getPrivateKey(),
                                                                          bobSignedPreKeyPair.getPublicKey().serialize());

            PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(), 1,
                                                      31337, bobPreKeyPair.getPublicKey(),
                                                      22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                                                      bobStore.GetIdentityKeyPair().getPublicKey());

            bobStore.StorePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
            bobStore.StoreSignedPreKey(22, new SignedPreKeyRecord(22, DateUtil.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

            aliceSessionBuilder.process(bobPreKey);

            String originalMessage = "L'homme est condamné à être libre";
            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, outgoingMessageOne.getType());

            byte[] goodMessage = outgoingMessageOne.serialize();
            byte[] badMessage = new byte[goodMessage.Length];
            Array.Copy(goodMessage, 0, badMessage, 0, badMessage.Length);

            badMessage[badMessage.Length - 10] ^= 0x01;

            PreKeyWhisperMessage incomingMessage = new PreKeyWhisperMessage(badMessage);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            byte[] plaintext = new byte[0];

            try
            {
                plaintext = bobSessionCipher.decrypt(incomingMessage);
                throw new Exception("Decrypt should have failed!");
            }
            catch (InvalidMessageException e)
            {
                // good.
            }

            Assert.IsTrue(bobStore.ContainsPreKey(31337));

            plaintext = bobSessionCipher.decrypt(new PreKeyWhisperMessage(goodMessage));

            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));
            Assert.IsFalse(bobStore.ContainsPreKey(31337));
        }

        [TestMethod, TestCategory("libaxolotl")]
        public void testBasicKeyExchange()
        {
            AxolotlStore aliceStore = new TestInMemoryAxolotlStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

            AxolotlStore bobStore = new TestInMemoryAxolotlStore();
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

            KeyExchangeMessage aliceKeyExchangeMessage = aliceSessionBuilder.process();
            Assert.IsNotNull(aliceKeyExchangeMessage);

            byte[] aliceKeyExchangeMessageBytes = aliceKeyExchangeMessage.serialize();
            KeyExchangeMessage bobKeyExchangeMessage = bobSessionBuilder.process(new KeyExchangeMessage(aliceKeyExchangeMessageBytes));

            Assert.IsNotNull(bobKeyExchangeMessage);

            byte[] bobKeyExchangeMessageBytes = bobKeyExchangeMessage.serialize();
            KeyExchangeMessage response = aliceSessionBuilder.process(new KeyExchangeMessage(bobKeyExchangeMessageBytes));

            Assert.IsNull(response);
            Assert.IsTrue(aliceStore.ContainsSession(BOB_ADDRESS));
            Assert.IsTrue(bobStore.ContainsSession(ALICE_ADDRESS));

            runInteraction(aliceStore, bobStore);

            aliceStore = new TestInMemoryAxolotlStore();
            aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            aliceKeyExchangeMessage = aliceSessionBuilder.process();

            try
            {
                bobKeyExchangeMessage = bobSessionBuilder.process(aliceKeyExchangeMessage);
                throw new Exception("This identity shouldn't be trusted!");
            }
            catch (UntrustedIdentityException uie)
            {
                bobStore.SaveIdentity(ALICE_ADDRESS.getName(), aliceKeyExchangeMessage.getIdentityKey());
                bobKeyExchangeMessage = bobSessionBuilder.process(aliceKeyExchangeMessage);
            }

            Assert.IsNull(aliceSessionBuilder.process(bobKeyExchangeMessage));

            runInteraction(aliceStore, bobStore);
        }

        [TestMethod, TestCategory("libaxolotl")]
        public void testSimultaneousKeyExchange()
        {
            AxolotlStore aliceStore = new TestInMemoryAxolotlStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

            AxolotlStore bobStore = new TestInMemoryAxolotlStore();
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

            KeyExchangeMessage aliceKeyExchange = aliceSessionBuilder.process();
            KeyExchangeMessage bobKeyExchange = bobSessionBuilder.process();

            Assert.IsNotNull(aliceKeyExchange);
            Assert.IsNotNull(bobKeyExchange);

            KeyExchangeMessage aliceResponse = aliceSessionBuilder.process(bobKeyExchange);
            KeyExchangeMessage bobResponse = bobSessionBuilder.process(aliceKeyExchange);

            Assert.IsNotNull(aliceResponse);
            Assert.IsNotNull(bobResponse);

            KeyExchangeMessage aliceAck = aliceSessionBuilder.process(bobResponse);
            KeyExchangeMessage bobAck = bobSessionBuilder.process(aliceResponse);

            Assert.IsNull(aliceAck);
            Assert.IsNull(bobAck);

            runInteraction(aliceStore, bobStore);
        }

        [TestMethod, TestCategory("libaxolotl")]
        public void testOptionalOneTimePreKey()
        {
            AxolotlStore aliceStore = new TestInMemoryAxolotlStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

            AxolotlStore bobStore = new TestInMemoryAxolotlStore();

            ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
            ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
            byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.GetIdentityKeyPair().getPrivateKey(),
                                                                          bobSignedPreKeyPair.getPublicKey().serialize());

            PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(), 1,
                                                      0, null,
                                                      22, bobSignedPreKeyPair.getPublicKey(),
                                                      bobSignedPreKeySignature,
                                                      bobStore.GetIdentityKeyPair().getPublicKey());

            aliceSessionBuilder.process(bobPreKey);

            Assert.IsTrue(aliceStore.ContainsSession(BOB_ADDRESS));
            Assert.AreEqual((uint)3, aliceStore.LoadSession(BOB_ADDRESS).getSessionState().getSessionVersion());

            String originalMessage = "L'homme est condamné à être libre";
            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            CiphertextMessage outgoingMessage = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(outgoingMessage.getType(), CiphertextMessage.PREKEY_TYPE);

            PreKeyWhisperMessage incomingMessage = new PreKeyWhisperMessage(outgoingMessage.serialize());
            Assert.IsFalse(incomingMessage.getPreKeyId().HasValue);

            bobStore.StorePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
            bobStore.StoreSignedPreKey(22, new SignedPreKeyRecord(22, DateUtil.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
            byte[] plaintext = bobSessionCipher.decrypt(incomingMessage);

            Assert.IsTrue(bobStore.ContainsSession(ALICE_ADDRESS));
            Assert.AreEqual((uint)3, bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getSessionVersion());
            Assert.IsNotNull(bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getAliceBaseKey());
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));
        }

        private void runInteraction(AxolotlStore aliceStore, AxolotlStore bobStore)
        {
            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            String originalMessage = "smert ze smert";
            CiphertextMessage aliceMessage = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, aliceMessage.getType());

            byte[] plaintext = bobSessionCipher.decrypt(new WhisperMessage(aliceMessage.serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            CiphertextMessage bobMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, bobMessage.getType());

            plaintext = aliceSessionCipher.decrypt(new WhisperMessage(bobMessage.serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            for (int i = 0; i < 10; i++)
            {
                String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                                         "We mean that man first of all exists, encounters himself, " +
                                         "surges up in the world--and defines himself aftward. " + i);
                CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(loopingMessage));

                byte[] loopingPlaintext = bobSessionCipher.decrypt(new WhisperMessage(aliceLoopingMessage.serialize()));
                Assert.AreEqual(loopingMessage, Encoding.UTF8.GetString(loopingPlaintext));
            }

            for (int i = 0; i < 10; i++)
            {
                String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                                         "We mean that man first of all exists, encounters himself, " +
                                         "surges up in the world--and defines himself aftward. " + i);
                CiphertextMessage bobLoopingMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes(loopingMessage));

                byte[] loopingPlaintext = aliceSessionCipher.decrypt(new WhisperMessage(bobLoopingMessage.serialize()));
                Assert.AreEqual(loopingMessage, Encoding.UTF8.GetString(loopingPlaintext));
            }

            HashSet<Pair<String, CiphertextMessage>> aliceOutOfOrderMessages = new HashSet<Pair<String, CiphertextMessage>>();

            for (int i = 0; i < 10; i++)
            {
                String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                                         "We mean that man first of all exists, encounters himself, " +
                                         "surges up in the world--and defines himself aftward. " + i);
                CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(loopingMessage));

                aliceOutOfOrderMessages.Add(new Pair<String, CiphertextMessage>(loopingMessage, aliceLoopingMessage));
            }

            for (int i = 0; i < 10; i++)
            {
                String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                                         "We mean that man first of all exists, encounters himself, " +
                                         "surges up in the world--and defines himself aftward. " + i);
                CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(loopingMessage));

                byte[] loopingPlaintext = bobSessionCipher.decrypt(new WhisperMessage(aliceLoopingMessage.serialize()));
                Assert.AreEqual(loopingMessage, Encoding.UTF8.GetString(loopingPlaintext));
            }

            for (int i = 0; i < 10; i++)
            {
                String loopingMessage = ("You can only desire based on what you know: " + i);
                CiphertextMessage bobLoopingMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes(loopingMessage));

                byte[] loopingPlaintext = aliceSessionCipher.decrypt(new WhisperMessage(bobLoopingMessage.serialize()));
                Assert.AreEqual(loopingMessage, Encoding.UTF8.GetString(loopingPlaintext));
            }

            foreach (Pair<String, CiphertextMessage> aliceOutOfOrderMessage in aliceOutOfOrderMessages)
            {
                byte[] outOfOrderPlaintext = bobSessionCipher.decrypt(new WhisperMessage(aliceOutOfOrderMessage.second().serialize()));
                Assert.AreEqual(aliceOutOfOrderMessage.first(), Encoding.UTF8.GetString(outOfOrderPlaintext));
            }
        }
    }
}
