using libaxolotl;
using libaxolotl.ecc;
using libaxolotl.protocol;
using libaxolotl.ratchet;
using libaxolotl.state;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Strilanc.Value;
using System;
using System.Collections.Generic;
using System.Text;

namespace libaxolotl_test
{
    [TestClass]
    public class SessionCipherTest
    {
        [TestMethod, TestCategory("libaxolotl")]
        public void testBasicSessionV2()
        {
            SessionRecord aliceSessionRecord = new SessionRecord();
            SessionRecord bobSessionRecord = new SessionRecord();

            initializeSessionsV2(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());
            runInteraction(aliceSessionRecord, bobSessionRecord);
        }

        [TestMethod, TestCategory("libaxolotl")]
        public void testBasicSessionV3()
        {
            SessionRecord aliceSessionRecord = new SessionRecord();
            SessionRecord bobSessionRecord = new SessionRecord();

            initializeSessionsV3(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());
            runInteraction(aliceSessionRecord, bobSessionRecord);
        }

        [TestMethod, TestCategory("libaxolotl")]
        public void testMessageKeyLimits()
        {
            SessionRecord aliceSessionRecord = new SessionRecord();
            SessionRecord bobSessionRecord = new SessionRecord();

            initializeSessionsV3(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());

            AxolotlStore aliceStore = new TestInMemoryAxolotlStore();
            AxolotlStore bobStore = new TestInMemoryAxolotlStore();

            aliceStore.StoreSession(new AxolotlAddress("+14159999999", 1), aliceSessionRecord);
            bobStore.StoreSession(new AxolotlAddress("+14158888888", 1), bobSessionRecord);

            SessionCipher aliceCipher = new SessionCipher(aliceStore, new AxolotlAddress("+14159999999", 1));
            SessionCipher bobCipher = new SessionCipher(bobStore, new AxolotlAddress("+14158888888", 1));

            List<CiphertextMessage> inflight = new List<CiphertextMessage>();

            for (int i = 0; i < 2010; i++)
            {
                inflight.Add(aliceCipher.encrypt(Encoding.UTF8.GetBytes("you've never been so hungry, you've never been so cold")));
            }

            bobCipher.decrypt(new WhisperMessage(inflight[1000].serialize()));
            bobCipher.decrypt(new WhisperMessage(inflight[inflight.Count - 1].serialize()));

            try
            {
                bobCipher.decrypt(new WhisperMessage(inflight[0].serialize()));
                throw new Exception("Should have failed!");
            }
            catch (DuplicateMessageException dme)
            {
                // good
            }
        }

        private void runInteraction(SessionRecord aliceSessionRecord, SessionRecord bobSessionRecord)
        {
            AxolotlStore aliceStore = new TestInMemoryAxolotlStore();
            AxolotlStore bobStore = new TestInMemoryAxolotlStore();

            aliceStore.StoreSession(new AxolotlAddress("+14159999999", 1), aliceSessionRecord);
            bobStore.StoreSession(new AxolotlAddress("+14158888888", 1), bobSessionRecord);

            SessionCipher aliceCipher = new SessionCipher(aliceStore, new AxolotlAddress("+14159999999", 1));
            SessionCipher bobCipher = new SessionCipher(bobStore, new AxolotlAddress("+14158888888", 1));

            byte[] alicePlaintext = Encoding.UTF8.GetBytes("This is a plaintext message.");
            CiphertextMessage message = aliceCipher.encrypt(alicePlaintext);
            byte[] bobPlaintext = bobCipher.decrypt(new WhisperMessage(message.serialize()));

            CollectionAssert.AreEqual(alicePlaintext, bobPlaintext);

            byte[] bobReply = Encoding.UTF8.GetBytes("This is a message from Bob.");
            CiphertextMessage reply = bobCipher.encrypt(bobReply);
            byte[] receivedReply = aliceCipher.decrypt(new WhisperMessage(reply.serialize()));

            CollectionAssert.AreEqual(bobReply, receivedReply);

            List<CiphertextMessage> aliceCiphertextMessages = new List<CiphertextMessage>();
            List<byte[]> alicePlaintextMessages = new List<byte[]>();

            for (int i = 0; i < 50; i++)
            {
                alicePlaintextMessages.Add(Encoding.UTF8.GetBytes("смерть за смерть " + i));
                aliceCiphertextMessages.Add(aliceCipher.encrypt(Encoding.UTF8.GetBytes("смерть за смерть " + i)));
            }

            ulong seed = DateUtil.currentTimeMillis();

            Shuffle(aliceCiphertextMessages, new Random((int)seed));
            Shuffle(alicePlaintextMessages, new Random((int)seed));

            for (int i = 0; i < aliceCiphertextMessages.Count / 2; i++)
            {
                byte[] receivedPlaintext = bobCipher.decrypt(new WhisperMessage(aliceCiphertextMessages[i].serialize()));
                CollectionAssert.AreEqual(receivedPlaintext, alicePlaintextMessages[i]);
            }

            List<CiphertextMessage> bobCiphertextMessages = new List<CiphertextMessage>();
            List<byte[]> bobPlaintextMessages = new List<byte[]>();

            for (int i = 0; i < 20; i++)
            {
                bobPlaintextMessages.Add(Encoding.UTF8.GetBytes("смерть за смерть " + i));
                bobCiphertextMessages.Add(bobCipher.encrypt(Encoding.UTF8.GetBytes("смерть за смерть " + i)));
            }

            seed = DateUtil.currentTimeMillis();

            Shuffle(bobCiphertextMessages, new Random((int)seed));
            Shuffle(bobPlaintextMessages, new Random((int)seed));

            for (int i = 0; i < bobCiphertextMessages.Count / 2; i++)
            {
                byte[] receivedPlaintext = aliceCipher.decrypt(new WhisperMessage(bobCiphertextMessages[i].serialize()));
                CollectionAssert.AreEqual(receivedPlaintext, bobPlaintextMessages[i]);
            }

            for (int i = aliceCiphertextMessages.Count / 2; i < aliceCiphertextMessages.Count; i++)
            {
                byte[] receivedPlaintext = bobCipher.decrypt(new WhisperMessage(aliceCiphertextMessages[i].serialize()));
                CollectionAssert.AreEqual(receivedPlaintext, alicePlaintextMessages[i]);
            }

            for (int i = bobCiphertextMessages.Count / 2; i < bobCiphertextMessages.Count; i++)
            {
                byte[] receivedPlaintext = aliceCipher.decrypt(new WhisperMessage(bobCiphertextMessages[i].serialize()));
                CollectionAssert.AreEqual(receivedPlaintext, bobPlaintextMessages[i]);
            }
        }

        private void initializeSessionsV2(SessionState aliceSessionState, SessionState bobSessionState)
        {
            ECKeyPair aliceIdentityKeyPair = Curve.generateKeyPair();
            IdentityKeyPair aliceIdentityKey = new IdentityKeyPair(new IdentityKey(aliceIdentityKeyPair.getPublicKey()),
                                                                   aliceIdentityKeyPair.getPrivateKey());
            ECKeyPair aliceBaseKey = Curve.generateKeyPair();
            ECKeyPair aliceEphemeralKey = Curve.generateKeyPair();

            ECKeyPair bobIdentityKeyPair = Curve.generateKeyPair();
            IdentityKeyPair bobIdentityKey = new IdentityKeyPair(new IdentityKey(bobIdentityKeyPair.getPublicKey()),
                                                                 bobIdentityKeyPair.getPrivateKey());
            ECKeyPair bobBaseKey = Curve.generateKeyPair();
            ECKeyPair bobEphemeralKey = bobBaseKey;

            AliceAxolotlParameters aliceParameters = AliceAxolotlParameters.newBuilder()
                .setOurIdentityKey(aliceIdentityKey)
                .setOurBaseKey(aliceBaseKey)
                .setTheirIdentityKey(bobIdentityKey.getPublicKey())
                .setTheirSignedPreKey(bobEphemeralKey.getPublicKey())
                .setTheirRatchetKey(bobEphemeralKey.getPublicKey())
                .setTheirOneTimePreKey(May<ECPublicKey>.NoValue)
                .create();

            BobAxolotlParameters bobParameters = BobAxolotlParameters.newBuilder()
                .setOurIdentityKey(bobIdentityKey)
                .setOurOneTimePreKey(May<ECKeyPair>.NoValue)
                .setOurRatchetKey(bobEphemeralKey)
                .setOurSignedPreKey(bobBaseKey)
                .setTheirBaseKey(aliceBaseKey.getPublicKey())
                .setTheirIdentityKey(aliceIdentityKey.getPublicKey())
                .create();

            RatchetingSession.initializeSession(aliceSessionState, 2, aliceParameters);
            RatchetingSession.initializeSession(bobSessionState, 2, bobParameters);
        }

        private void initializeSessionsV3(SessionState aliceSessionState, SessionState bobSessionState)
        {
            ECKeyPair aliceIdentityKeyPair = Curve.generateKeyPair();
            IdentityKeyPair aliceIdentityKey = new IdentityKeyPair(new IdentityKey(aliceIdentityKeyPair.getPublicKey()),
                                                                   aliceIdentityKeyPair.getPrivateKey());
            ECKeyPair aliceBaseKey = Curve.generateKeyPair();
            ECKeyPair aliceEphemeralKey = Curve.generateKeyPair();

            ECKeyPair alicePreKey = aliceBaseKey;

            ECKeyPair bobIdentityKeyPair = Curve.generateKeyPair();
            IdentityKeyPair bobIdentityKey = new IdentityKeyPair(new IdentityKey(bobIdentityKeyPair.getPublicKey()),
                                                                 bobIdentityKeyPair.getPrivateKey());
            ECKeyPair bobBaseKey = Curve.generateKeyPair();
            ECKeyPair bobEphemeralKey = bobBaseKey;

            ECKeyPair bobPreKey = Curve.generateKeyPair();

            AliceAxolotlParameters aliceParameters = AliceAxolotlParameters.newBuilder()
                .setOurBaseKey(aliceBaseKey)
                .setOurIdentityKey(aliceIdentityKey)
                .setTheirOneTimePreKey(May<ECPublicKey>.NoValue)
                .setTheirRatchetKey(bobEphemeralKey.getPublicKey())
                .setTheirSignedPreKey(bobBaseKey.getPublicKey())
                .setTheirIdentityKey(bobIdentityKey.getPublicKey())
                .create();

            BobAxolotlParameters bobParameters = BobAxolotlParameters.newBuilder()
                .setOurRatchetKey(bobEphemeralKey)
                .setOurSignedPreKey(bobBaseKey)
                .setOurOneTimePreKey(May<ECKeyPair>.NoValue)
                .setOurIdentityKey(bobIdentityKey)
                .setTheirIdentityKey(aliceIdentityKey.getPublicKey())
                .setTheirBaseKey(aliceBaseKey.getPublicKey())
                .create();

            RatchetingSession.initializeSession(aliceSessionState, 3, aliceParameters);
            RatchetingSession.initializeSession(bobSessionState, 3, bobParameters);
        }

        public static void Shuffle<T>(IList<T> list, Random rng)
        {
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
