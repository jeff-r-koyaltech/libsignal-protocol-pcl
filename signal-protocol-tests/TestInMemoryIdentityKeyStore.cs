using libaxolotl;
using libaxolotl.ecc;
using libaxolotl.state.impl;
using libaxolotl.util;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libaxolotl_test
{
    class TestInMemoryIdentityKeyStore : InMemoryIdentityKeyStore
    {
        public TestInMemoryIdentityKeyStore()
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
