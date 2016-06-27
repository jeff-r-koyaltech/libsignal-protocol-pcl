using libaxolotl.ecc.impl;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace signal_protocol_pcl.ecc.impl
{
    class Curve25519ManagedProvider : ICurve25519Provider
    {
        public byte[] calculateAgreement(byte[] ourPrivate, byte[] theirPublic)
        {
            return null;//todo
        }

        public byte[] calculateSignature(byte[] random, byte[] privateKey, byte[] message)
        {
            throw new NotImplementedException();
        }

        public byte[] generatePrivateKey(byte[] random)
        {
            throw new NotImplementedException();
        }

        public byte[] generatePublicKey(byte[] privateKey)
        {
            throw new NotImplementedException();
        }

        public bool isNative()
        {
            throw new NotImplementedException();
        }

        public bool verifySignature(byte[] publicKey, byte[] message, byte[] signature)
        {
            throw new NotImplementedException();
        }
    }
}
