using libaxolotl;
using libaxolotl.groups;
using libaxolotl.protocol;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using static PCLCrypto.WinRTCrypto;
using System;
using System.Collections.Generic;
using System.Text;

namespace libaxolotl_test.groups
{
    [TestClass]
    public class GroupCipherTest
    {
        private static readonly AxolotlAddress SENDER_ADDRESS = new AxolotlAddress("+14150001111", 1);
        private static readonly SenderKeyName GROUP_SENDER = new SenderKeyName("nihilist history reading group", SENDER_ADDRESS);

        [TestMethod, TestCategory("libaxolotl.groups")]
        public void testNoSession()
        {
            InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
            InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

            GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
            GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GROUP_SENDER);
            GroupCipher bobGroupCipher = new GroupCipher(bobStore, GROUP_SENDER);

            SenderKeyDistributionMessage sentAliceDistributionMessage = aliceSessionBuilder.create(GROUP_SENDER);
            SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());

            //    bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

            byte[] ciphertextFromAlice = aliceGroupCipher.encrypt(Encoding.UTF8.GetBytes("smert ze smert"));
            try
            {
                byte[] plaintextFromAlice = bobGroupCipher.decrypt(ciphertextFromAlice);
                throw new Exception("Should be no session!");
            }
            catch (NoSessionException e)
            {
                // good
            }
        }

        [TestMethod, TestCategory("libaxolotl.groups")]
        public void testBasicEncryptDecrypt()
        {
            InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
            InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

            GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
            GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GROUP_SENDER);
            GroupCipher bobGroupCipher = new GroupCipher(bobStore, GROUP_SENDER);

            SenderKeyDistributionMessage sentAliceDistributionMessage = aliceSessionBuilder.create(GROUP_SENDER);
            SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());
            bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

            byte[] ciphertextFromAlice = aliceGroupCipher.encrypt(Encoding.UTF8.GetBytes("smert ze smert"));
            byte[] plaintextFromAlice = bobGroupCipher.decrypt(ciphertextFromAlice);

            Assert.AreEqual("smert ze smert", Encoding.UTF8.GetString(plaintextFromAlice));
        }

        [TestMethod, TestCategory("libaxolotl.groups")]
        public void testLargeMessages()
        {
            InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
            InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

            GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
            GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GROUP_SENDER);
            GroupCipher bobGroupCipher = new GroupCipher(bobStore, GROUP_SENDER);

            SenderKeyDistributionMessage sentAliceDistributionMessage = aliceSessionBuilder.create(GROUP_SENDER);
            SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());
            bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

            byte[] plaintext = new byte[1024 * 1024];
            new Random().NextBytes(plaintext);

            byte[] ciphertextFromAlice = aliceGroupCipher.encrypt(plaintext);
            byte[] plaintextFromAlice = bobGroupCipher.decrypt(ciphertextFromAlice);

            CollectionAssert.AreEqual(plaintext, plaintextFromAlice);
        }

        [TestMethod, TestCategory("libaxolotl.groups")]
        public void testBasicRatchet()
        {
            InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
            InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

            GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
            GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

            SenderKeyName aliceName = GROUP_SENDER;

            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
            GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);

            SenderKeyDistributionMessage sentAliceDistributionMessage =
                aliceSessionBuilder.create(aliceName);
            SenderKeyDistributionMessage receivedAliceDistributionMessage =
                new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());

            bobSessionBuilder.process(aliceName, receivedAliceDistributionMessage);

            byte[] ciphertextFromAlice = aliceGroupCipher.encrypt(Encoding.UTF8.GetBytes("smert ze smert"));
            byte[] ciphertextFromAlice2 = aliceGroupCipher.encrypt(Encoding.UTF8.GetBytes("smert ze smert2"));
            byte[] ciphertextFromAlice3 = aliceGroupCipher.encrypt(Encoding.UTF8.GetBytes("smert ze smert3"));

            byte[] plaintextFromAlice = bobGroupCipher.decrypt(ciphertextFromAlice);

            try
            {
                bobGroupCipher.decrypt(ciphertextFromAlice);
                throw new Exception("Should have ratcheted forward!");
            }
            catch (DuplicateMessageException dme)
            {
                // good
            }

            byte[] plaintextFromAlice2 = bobGroupCipher.decrypt(ciphertextFromAlice2);
            byte[] plaintextFromAlice3 = bobGroupCipher.decrypt(ciphertextFromAlice3);

            Assert.AreEqual("smert ze smert", Encoding.UTF8.GetString(plaintextFromAlice));
            Assert.AreEqual("smert ze smert2", Encoding.UTF8.GetString(plaintextFromAlice2));
            Assert.AreEqual("smert ze smert3", Encoding.UTF8.GetString(plaintextFromAlice3));
        }

        [TestMethod, TestCategory("libaxolotl.groups")]
        public void testLateJoin()
        {
            InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
            InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

            GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);


            SenderKeyName aliceName = GROUP_SENDER;

            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);


            SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.create(aliceName);
            // Send off to some people.

            for (int i = 0; i < 100; i++)
            {
                aliceGroupCipher.encrypt(Encoding.UTF8.GetBytes("up the punks up the punks up the punks"));
            }

            // Now Bob Joins.
            GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);
            GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);


            SenderKeyDistributionMessage distributionMessageToBob = aliceSessionBuilder.create(aliceName);
            bobSessionBuilder.process(aliceName, new SenderKeyDistributionMessage(distributionMessageToBob.serialize()));

            byte[] ciphertext = aliceGroupCipher.encrypt(Encoding.UTF8.GetBytes("welcome to the group"));
            byte[] plaintext = bobGroupCipher.decrypt(ciphertext);

            Assert.AreEqual("welcome to the group", Encoding.UTF8.GetString(plaintext));
        }

        [TestMethod, TestCategory("libaxolotl.groups")]
        public void testOutOfOrder()
        {
            InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
            InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

            GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
            GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

            SenderKeyName aliceName = GROUP_SENDER;

            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
            GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);

            SenderKeyDistributionMessage aliceDistributionMessage =
                aliceSessionBuilder.create(aliceName);

            bobSessionBuilder.process(aliceName, aliceDistributionMessage);

            List<byte[]> ciphertexts = new List<byte[]>(100);

            for (int i = 0; i < 100; i++)
            {
                ciphertexts.Add(aliceGroupCipher.encrypt(Encoding.UTF8.GetBytes("up the punks")));
            }

            while (ciphertexts.Count > 0)
            {
                int index = (int)(randomUInt() % ciphertexts.Count);
                byte[] ciphertext = ciphertexts[index];
                ciphertexts.RemoveAt(index);
                byte[] plaintext = bobGroupCipher.decrypt(ciphertext);

                Assert.AreEqual("up the punks", Encoding.UTF8.GetString(plaintext));
            }
        }

        [TestMethod, TestCategory("libaxolotl.groups")]
        public void testEncryptNoSession()
        {
            InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, new SenderKeyName("coolio groupio", new AxolotlAddress("+10002223333", 1)));
            try
            {
                aliceGroupCipher.encrypt(Encoding.UTF8.GetBytes("up the punks"));
                throw new Exception("Should have failed!");
            }
            catch (NoSessionException nse)
            {
                // good
            }
        }

        [TestMethod, TestCategory("libaxolotl.groups")]
        public void testTooFarInFuture()
        {
            InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
            InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

            GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
            GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

            SenderKeyName aliceName = GROUP_SENDER;

            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
            GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);

            SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.create(aliceName);

            bobSessionBuilder.process(aliceName, aliceDistributionMessage);

            for (int i = 0; i < 2001; i++)
            {
                aliceGroupCipher.encrypt(Encoding.UTF8.GetBytes("up the punks"));
            }

            byte[] tooFarCiphertext = aliceGroupCipher.encrypt(Encoding.UTF8.GetBytes("notta gonna worka"));
            try
            {
                bobGroupCipher.decrypt(tooFarCiphertext);
                throw new Exception("Should have failed!");
            }
            catch (InvalidMessageException e)
            {
                // good
            }
        }

        [TestMethod, TestCategory("libaxolotl.groups")]
        public void testMessageKeyLimit()
        {
            InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
            InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

            GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
            GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

            SenderKeyName aliceName = GROUP_SENDER;

            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
            GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);

            SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.create(aliceName);

            bobSessionBuilder.process(aliceName, aliceDistributionMessage);

            List<byte[]> inflight = new List<byte[]>();

            for (int i = 0; i < 2010; i++)
            {
                inflight.Add(aliceGroupCipher.encrypt(Encoding.UTF8.GetBytes("up the punks")));
            }

            bobGroupCipher.decrypt(inflight[1000]);
            bobGroupCipher.decrypt(inflight[inflight.Count - 1]);

            try
            {
                bobGroupCipher.decrypt(inflight[0]);
                throw new Exception("Should have failed!");
            }
            catch (DuplicateMessageException e)
            {
                // good
            }
        }

        private uint randomUInt()
        {

            byte[] randomBytes = CryptographicBuffer.GenerateRandom(4);
            return BitConverter.ToUInt32(randomBytes, 0);
        }
    }
}
