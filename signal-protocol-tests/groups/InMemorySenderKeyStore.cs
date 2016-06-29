using libaxolotl.groups;
using libaxolotl.groups.state;
using System;
using System.Collections.Generic;
using System.IO;

namespace libaxolotl_test.groups
{
    class InMemorySenderKeyStore : SenderKeyStore
    {
        private readonly Dictionary<SenderKeyName, SenderKeyRecord> store = new Dictionary<SenderKeyName, SenderKeyRecord>();

        public void storeSenderKey(SenderKeyName senderKeyName, SenderKeyRecord record)
        {
            store[senderKeyName] = record;
        }

        public SenderKeyRecord loadSenderKey(SenderKeyName senderKeyName)
        {
            try
            {
                SenderKeyRecord record;
                store.TryGetValue(senderKeyName, out record);

                if (record == null)
                {
                    return new SenderKeyRecord();
                }
                else
                {
                    return new SenderKeyRecord(record.serialize());
                }
            }
            catch (IOException e)
            {
                throw new Exception(e.Message);
            }
        }
    }
}
