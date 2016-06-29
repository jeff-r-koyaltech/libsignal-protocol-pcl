using libaxolotl;
using libaxolotl.ecc;
using libaxolotl.protocol;
using libaxolotl.state;
using libaxolotl.util;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Text;

namespace libaxolotl_test
{
    [TestClass]
    public class SimultaneousInitiateTests
    {
        private static readonly AxolotlAddress BOB_ADDRESS = new AxolotlAddress("+14151231234", 1);
        private static readonly AxolotlAddress ALICE_ADDRESS = new AxolotlAddress("+14159998888", 1);

        private static readonly ECKeyPair aliceSignedPreKey = Curve.generateKeyPair();
        private static readonly ECKeyPair bobSignedPreKey = Curve.generateKeyPair();

        private static readonly uint aliceSignedPreKeyId = (uint)new Random().Next((int)Medium.MAX_VALUE);
        private static readonly uint bobSignedPreKeyId = (uint)new Random().Next((int)Medium.MAX_VALUE);

        [TestMethod, TestCategory("libaxolotl")]
        public void testBasicSimultaneousInitiate()
        {
            AxolotlStore aliceStore = new TestInMemoryAxolotlStore();
            AxolotlStore bobStore = new TestInMemoryAxolotlStore();

            PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            aliceSessionBuilder.process(bobPreKeyBundle);
            bobSessionBuilder.process(alicePreKeyBundle);

            CiphertextMessage messageForBob = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
            CiphertextMessage messageForAlice = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, messageForBob.getType());
            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, messageForAlice.getType());

            Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeyWhisperMessage(messageForAlice.serialize()));
            byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeyWhisperMessage(messageForBob.serialize()));

            Assert.AreEqual("sample message", Encoding.UTF8.GetString(alicePlaintext));
            Assert.AreEqual("hey there", Encoding.UTF8.GetString(bobPlaintext));

            Assert.AreEqual((uint)3, aliceStore.LoadSession(BOB_ADDRESS).getSessionState().getSessionVersion());
            Assert.AreEqual((uint)3, bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getSessionVersion());

            Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage aliceResponse = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("second message"));

            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, aliceResponse.getType());

            byte[] responsePlaintext = bobSessionCipher.decrypt(new WhisperMessage(aliceResponse.serialize()));

            Assert.AreEqual("second message", Encoding.UTF8.GetString(responsePlaintext));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage finalMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("third message"));

            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, finalMessage.getType());

            byte[] finalPlaintext = aliceSessionCipher.decrypt(new WhisperMessage(finalMessage.serialize()));

            Assert.AreEqual("third message", Encoding.UTF8.GetString(finalPlaintext));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));
        }

        [TestMethod, TestCategory("libaxolotl")]
        public void testLostSimultaneousInitiate()
        {
            AxolotlStore aliceStore = new TestInMemoryAxolotlStore();
            AxolotlStore bobStore = new TestInMemoryAxolotlStore();

            PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            aliceSessionBuilder.process(bobPreKeyBundle);
            bobSessionBuilder.process(alicePreKeyBundle);

            CiphertextMessage messageForBob = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
            CiphertextMessage messageForAlice = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, messageForBob.getType());
            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, messageForAlice.getType());

            Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

            byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeyWhisperMessage(messageForBob.serialize()));

            Assert.AreEqual("hey there", Encoding.UTF8.GetString(bobPlaintext));
            Assert.AreEqual((uint)3, bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getSessionVersion());

            CiphertextMessage aliceResponse = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("second message"));

            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, aliceResponse.getType());

            byte[] responsePlaintext = bobSessionCipher.decrypt(new PreKeyWhisperMessage(aliceResponse.serialize()));

            Assert.AreEqual("second message", Encoding.UTF8.GetString(responsePlaintext));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage finalMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("third message"));

            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, finalMessage.getType());

            byte[] finalPlaintext = aliceSessionCipher.decrypt(new WhisperMessage(finalMessage.serialize()));

            Assert.AreEqual("third message", Encoding.UTF8.GetString(finalPlaintext));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));
        }

        [TestMethod, TestCategory("libaxolotl")]
        public void testSimultaneousInitiateLostMessage()
        {
            AxolotlStore aliceStore = new TestInMemoryAxolotlStore();
            AxolotlStore bobStore = new TestInMemoryAxolotlStore();

            PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            aliceSessionBuilder.process(bobPreKeyBundle);
            bobSessionBuilder.process(alicePreKeyBundle);

            CiphertextMessage messageForBob = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
            CiphertextMessage messageForAlice = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, messageForBob.getType());
            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, messageForAlice.getType());

            Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeyWhisperMessage(messageForAlice.serialize()));
            byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeyWhisperMessage(messageForBob.serialize()));

            Assert.AreEqual("sample message", Encoding.UTF8.GetString(alicePlaintext));
            Assert.AreEqual("hey there", Encoding.UTF8.GetString(bobPlaintext));

            Assert.AreEqual((uint)3, aliceStore.LoadSession(BOB_ADDRESS).getSessionState().getSessionVersion());
            Assert.AreEqual((uint)3, bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getSessionVersion());

            Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage aliceResponse = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("second message"));

            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, aliceResponse.getType());

            //    byte[] responsePlaintext = bobSessionCipher.decrypt(new WhisperMessage(aliceResponse.serialize()));
            //
            //    assertTrue(new String(responsePlaintext).equals("second message"));
            //    assertTrue(isSessionIdEqual(aliceStore, bobStore));
            Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage finalMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("third message"));

            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, finalMessage.getType());

            byte[] finalPlaintext = aliceSessionCipher.decrypt(new WhisperMessage(finalMessage.serialize()));

            Assert.AreEqual("third message", Encoding.UTF8.GetString(finalPlaintext));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));
        }

        [TestMethod, TestCategory("libaxolotl")]
        public void testSimultaneousInitiateRepeatedMessages()
        {
            AxolotlStore aliceStore = new TestInMemoryAxolotlStore();
            AxolotlStore bobStore = new TestInMemoryAxolotlStore();

            PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            aliceSessionBuilder.process(bobPreKeyBundle);
            bobSessionBuilder.process(alicePreKeyBundle);

            CiphertextMessage messageForBob = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
            CiphertextMessage messageForAlice = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, messageForBob.getType());
            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, messageForAlice.getType());

            Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeyWhisperMessage(messageForAlice.serialize()));
            byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeyWhisperMessage(messageForBob.serialize()));

            Assert.AreEqual("sample message", Encoding.UTF8.GetString(alicePlaintext));
            Assert.AreEqual("hey there", Encoding.UTF8.GetString(bobPlaintext));

            Assert.AreEqual((uint)3, aliceStore.LoadSession(BOB_ADDRESS).getSessionState().getSessionVersion());
            Assert.AreEqual((uint)3, bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getSessionVersion());

            Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

            for (int i = 0; i < 50; i++)
            {
                CiphertextMessage messageForBobRepeat = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
                CiphertextMessage messageForAliceRepeat = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

                Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, messageForBobRepeat.getType());
                Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, messageForAliceRepeat.getType());

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

                byte[] alicePlaintextRepeat = aliceSessionCipher.decrypt(new WhisperMessage(messageForAliceRepeat.serialize()));
                byte[] bobPlaintextRepeat = bobSessionCipher.decrypt(new WhisperMessage(messageForBobRepeat.serialize()));

                Assert.AreEqual("sample message", Encoding.UTF8.GetString(alicePlaintextRepeat));
                Assert.AreEqual("hey there", Encoding.UTF8.GetString(bobPlaintextRepeat));

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));
            }

            CiphertextMessage aliceResponse = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("second message"));

            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, aliceResponse.getType());

            byte[] responsePlaintext = bobSessionCipher.decrypt(new WhisperMessage(aliceResponse.serialize()));

            Assert.AreEqual("second message", Encoding.UTF8.GetString(responsePlaintext));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage finalMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("third message"));

            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, finalMessage.getType());

            byte[] finalPlaintext = aliceSessionCipher.decrypt(new WhisperMessage(finalMessage.serialize()));

            Assert.AreEqual("third message", Encoding.UTF8.GetString(finalPlaintext));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));
        }

        [TestMethod, TestCategory("libaxolotl")]
        public void testRepeatedSimultaneousInitiateRepeatedMessages()
        {
            AxolotlStore aliceStore = new TestInMemoryAxolotlStore();
            AxolotlStore bobStore = new TestInMemoryAxolotlStore();


            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            for (int i = 0; i < 15; i++)
            {
                PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
                PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

                aliceSessionBuilder.process(bobPreKeyBundle);
                bobSessionBuilder.process(alicePreKeyBundle);

                CiphertextMessage messageForBob = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
                CiphertextMessage messageForAlice = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

                Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, messageForBob.getType());
                Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, messageForAlice.getType());

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

                byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeyWhisperMessage(messageForAlice.serialize()));
                byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeyWhisperMessage(messageForBob.serialize()));

                Assert.AreEqual("sample message", Encoding.UTF8.GetString(alicePlaintext));
                Assert.AreEqual("hey there", Encoding.UTF8.GetString(bobPlaintext));

                Assert.AreEqual((uint)3, aliceStore.LoadSession(BOB_ADDRESS).getSessionState().getSessionVersion());
                Assert.AreEqual((uint)3, bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getSessionVersion());

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));
            }

            for (int i = 0; i < 50; i++)
            {
                CiphertextMessage messageForBobRepeat = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
                CiphertextMessage messageForAliceRepeat = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

                Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, messageForBobRepeat.getType());
                Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, messageForAliceRepeat.getType());

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

                byte[] alicePlaintextRepeat = aliceSessionCipher.decrypt(new WhisperMessage(messageForAliceRepeat.serialize()));
                byte[] bobPlaintextRepeat = bobSessionCipher.decrypt(new WhisperMessage(messageForBobRepeat.serialize()));

                Assert.AreEqual("sample message", Encoding.UTF8.GetString(alicePlaintextRepeat));
                Assert.AreEqual("hey there", Encoding.UTF8.GetString(bobPlaintextRepeat));

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));
            }

            CiphertextMessage aliceResponse = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("second message"));

            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, aliceResponse.getType());

            byte[] responsePlaintext = bobSessionCipher.decrypt(new WhisperMessage(aliceResponse.serialize()));

            Assert.AreEqual("second message", Encoding.UTF8.GetString(responsePlaintext));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage finalMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("third message"));

            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, finalMessage.getType());

            byte[] finalPlaintext = aliceSessionCipher.decrypt(new WhisperMessage(finalMessage.serialize()));

            Assert.AreEqual("third message", Encoding.UTF8.GetString(finalPlaintext));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));
        }

        [TestMethod, TestCategory("libaxolotl")]
        public void testRepeatedSimultaneousInitiateLostMessageRepeatedMessages()
        {
            AxolotlStore aliceStore = new TestInMemoryAxolotlStore();
            AxolotlStore bobStore = new TestInMemoryAxolotlStore();


            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            //    PreKeyBundle aliceLostPreKeyBundle = createAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobLostPreKeyBundle = createBobPreKeyBundle(bobStore);

            aliceSessionBuilder.process(bobLostPreKeyBundle);
            //    bobSessionBuilder.process(aliceLostPreKeyBundle);

            CiphertextMessage lostMessageForBob = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
            //    CiphertextMessage lostMessageForAlice = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

            for (int i = 0; i < 15; i++)
            {
                PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
                PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

                aliceSessionBuilder.process(bobPreKeyBundle);
                bobSessionBuilder.process(alicePreKeyBundle);

                CiphertextMessage messageForBob = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
                CiphertextMessage messageForAlice = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

                Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, messageForBob.getType());
                Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, messageForAlice.getType());

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

                byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeyWhisperMessage(messageForAlice.serialize()));
                byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeyWhisperMessage(messageForBob.serialize()));

                Assert.AreEqual("sample message", Encoding.UTF8.GetString(alicePlaintext));
                Assert.AreEqual("hey there", Encoding.UTF8.GetString(bobPlaintext));

                Assert.AreEqual((uint)3, aliceStore.LoadSession(BOB_ADDRESS).getSessionState().getSessionVersion());
                Assert.AreEqual((uint)3, bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getSessionVersion());

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));
            }

            for (int i = 0; i < 50; i++)
            {
                CiphertextMessage messageForBobRepeat = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
                CiphertextMessage messageForAliceRepeat = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

                Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, messageForBobRepeat.getType());
                Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, messageForAliceRepeat.getType());

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

                byte[] alicePlaintextRepeat = aliceSessionCipher.decrypt(new WhisperMessage(messageForAliceRepeat.serialize()));
                byte[] bobPlaintextRepeat = bobSessionCipher.decrypt(new WhisperMessage(messageForBobRepeat.serialize()));

                Assert.AreEqual("sample message", Encoding.UTF8.GetString(alicePlaintextRepeat));
                Assert.AreEqual("hey there", Encoding.UTF8.GetString(bobPlaintextRepeat));

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));
            }

            CiphertextMessage aliceResponse = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("second message"));

            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, aliceResponse.getType());

            byte[] responsePlaintext = bobSessionCipher.decrypt(new WhisperMessage(aliceResponse.serialize()));

            Assert.AreEqual("second message", Encoding.UTF8.GetString(responsePlaintext));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage finalMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("third message"));

            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, finalMessage.getType());

            byte[] finalPlaintext = aliceSessionCipher.decrypt(new WhisperMessage(finalMessage.serialize()));

            Assert.AreEqual("third message", Encoding.UTF8.GetString(finalPlaintext));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));

            byte[] lostMessagePlaintext = bobSessionCipher.decrypt(new PreKeyWhisperMessage(lostMessageForBob.serialize()));
            Assert.AreEqual("hey there", Encoding.UTF8.GetString(lostMessagePlaintext));

            Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage blastFromThePast = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("unexpected!"));
            byte[] blastFromThePastPlaintext = aliceSessionCipher.decrypt(new WhisperMessage(blastFromThePast.serialize()));

            Assert.AreEqual("unexpected!", Encoding.UTF8.GetString(blastFromThePastPlaintext));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));
        }

        private bool isSessionIdEqual(AxolotlStore aliceStore, AxolotlStore bobStore)
        {
            return Enumerable.SequenceEqual(aliceStore.LoadSession(BOB_ADDRESS).getSessionState().getAliceBaseKey(),
                                            bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getAliceBaseKey());
        }

        private PreKeyBundle createAlicePreKeyBundle(AxolotlStore aliceStore)
        {
            ECKeyPair aliceUnsignedPreKey = Curve.generateKeyPair();
            uint aliceUnsignedPreKeyId = (uint)new Random().Next((int)Medium.MAX_VALUE);
            byte[] aliceSignature = Curve.calculateSignature(aliceStore.GetIdentityKeyPair().getPrivateKey(),
                                                                       aliceSignedPreKey.getPublicKey().serialize());

            PreKeyBundle alicePreKeyBundle = new PreKeyBundle(1, 1,
                                                              aliceUnsignedPreKeyId, aliceUnsignedPreKey.getPublicKey(),
                                                              aliceSignedPreKeyId, aliceSignedPreKey.getPublicKey(),
                                                              aliceSignature, aliceStore.GetIdentityKeyPair().getPublicKey());

            aliceStore.StoreSignedPreKey(aliceSignedPreKeyId, new SignedPreKeyRecord(aliceSignedPreKeyId, DateUtil.currentTimeMillis(), aliceSignedPreKey, aliceSignature));
            aliceStore.StorePreKey(aliceUnsignedPreKeyId, new PreKeyRecord(aliceUnsignedPreKeyId, aliceUnsignedPreKey));

            return alicePreKeyBundle;
        }

        private PreKeyBundle createBobPreKeyBundle(AxolotlStore bobStore)
        {
            ECKeyPair bobUnsignedPreKey = Curve.generateKeyPair();
            uint bobUnsignedPreKeyId = (uint)new Random().Next((int)Medium.MAX_VALUE);
            byte[] bobSignature = Curve.calculateSignature(bobStore.GetIdentityKeyPair().getPrivateKey(),
                                                                     bobSignedPreKey.getPublicKey().serialize());

            PreKeyBundle bobPreKeyBundle = new PreKeyBundle(1, 1,
                                                        bobUnsignedPreKeyId, bobUnsignedPreKey.getPublicKey(),
                                                        bobSignedPreKeyId, bobSignedPreKey.getPublicKey(),
                                                        bobSignature, bobStore.GetIdentityKeyPair().getPublicKey());

            bobStore.StoreSignedPreKey(bobSignedPreKeyId, new SignedPreKeyRecord(bobSignedPreKeyId, DateUtil.currentTimeMillis(), bobSignedPreKey, bobSignature));
            bobStore.StorePreKey(bobUnsignedPreKeyId, new PreKeyRecord(bobUnsignedPreKeyId, bobUnsignedPreKey));

            return bobPreKeyBundle;
        }
    }
}
