using libaxolotl;
using libaxolotl.ecc;
using libaxolotl.state.impl;
using libaxolotl.util;

namespace libaxolotl_test
{
    class TestInMemoryAxolotlStore : InMemoryAxolotlStore
    {
        public TestInMemoryAxolotlStore()
            : base(generateIdentityKeyPair(), generateRegistrationId())
        { }

        private static IdentityKeyPair generateIdentityKeyPair()
        {
            ECKeyPair identityKeyPairKeys = Curve.generateKeyPair();

            return new IdentityKeyPair(new IdentityKey(identityKeyPairKeys.getPublicKey()),
                                                       identityKeyPairKeys.getPrivateKey());
        }

        private static uint generateRegistrationId()
        {
            return KeyHelper.generateRegistrationId(false);
        }
    }
}
