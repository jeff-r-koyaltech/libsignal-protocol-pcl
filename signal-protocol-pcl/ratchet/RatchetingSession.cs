/** 
 * Copyright (C) 2015 smndtrl
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

using libaxolotl.ecc;
using libaxolotl.kdf;
using libaxolotl.state;
using libaxolotl.util;
using Strilanc.Value;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libaxolotl.ratchet
{
    public class RatchetingSession
    {

        public static void initializeSession(SessionState sessionState,
                                             uint sessionVersion,
                                             SymmetricAxolotlParameters parameters)
        {
            if (isAlice(parameters.getOurBaseKey().getPublicKey(), parameters.getTheirBaseKey()))
            {
                AliceAxolotlParameters.Builder aliceParameters = AliceAxolotlParameters.newBuilder();

                aliceParameters.setOurBaseKey(parameters.getOurBaseKey())
                               .setOurIdentityKey(parameters.getOurIdentityKey())
                               .setTheirRatchetKey(parameters.getTheirRatchetKey())
                               .setTheirIdentityKey(parameters.getTheirIdentityKey())
                               .setTheirSignedPreKey(parameters.getTheirBaseKey())
                               .setTheirOneTimePreKey(May<ECPublicKey>.NoValue);

                RatchetingSession.initializeSession(sessionState, sessionVersion, aliceParameters.create());
            }
            else
            {
                BobAxolotlParameters.Builder bobParameters = BobAxolotlParameters.newBuilder();

                bobParameters.setOurIdentityKey(parameters.getOurIdentityKey())
                             .setOurRatchetKey(parameters.getOurRatchetKey())
                             .setOurSignedPreKey(parameters.getOurBaseKey())
                             .setOurOneTimePreKey(May<ECKeyPair>.NoValue)
                             .setTheirBaseKey(parameters.getTheirBaseKey())
                             .setTheirIdentityKey(parameters.getTheirIdentityKey());

                RatchetingSession.initializeSession(sessionState, sessionVersion, bobParameters.create());
            }
        }

        public static void initializeSession(SessionState sessionState,
                                             uint sessionVersion,
                                             AliceAxolotlParameters parameters)

        {
            try
            {
                sessionState.setSessionVersion(sessionVersion);
                sessionState.setRemoteIdentityKey(parameters.getTheirIdentityKey());
                sessionState.setLocalIdentityKey(parameters.getOurIdentityKey().getPublicKey());

                ECKeyPair sendingRatchetKey = Curve.generateKeyPair();
                MemoryStream secrets = new MemoryStream();

                if (sessionVersion >= 3)
                {
                    byte[] discontinuityBytes = getDiscontinuityBytes();
                    secrets.Write(discontinuityBytes, 0, discontinuityBytes.Length);
                }

                byte[] agree1 = Curve.calculateAgreement(parameters.getTheirSignedPreKey(),
                                                       parameters.getOurIdentityKey().getPrivateKey());
                byte[] agree2 = Curve.calculateAgreement(parameters.getTheirIdentityKey().getPublicKey(),
                                                        parameters.getOurBaseKey().getPrivateKey());
                byte[] agree3 = Curve.calculateAgreement(parameters.getTheirSignedPreKey(),
                                                       parameters.getOurBaseKey().getPrivateKey());

                secrets.Write(agree1, 0, agree1.Length);
                secrets.Write(agree2, 0, agree2.Length);
                secrets.Write(agree3, 0, agree3.Length);


                if (sessionVersion >= 3 && parameters.getTheirOneTimePreKey().HasValue)
                {
                    byte[] agree4 = Curve.calculateAgreement(parameters.getTheirOneTimePreKey().ForceGetValue(),
                                                           parameters.getOurBaseKey().getPrivateKey());
                    secrets.Write(agree4, 0, agree4.Length);
                }

                DerivedKeys derivedKeys = calculateDerivedKeys(sessionVersion, secrets.ToArray());
                Pair<RootKey, ChainKey> sendingChain = derivedKeys.getRootKey().createChain(parameters.getTheirRatchetKey(), sendingRatchetKey);

                sessionState.addReceiverChain(parameters.getTheirRatchetKey(), derivedKeys.getChainKey());
                sessionState.setSenderChain(sendingRatchetKey, sendingChain.second());
                sessionState.setRootKey(sendingChain.first());
            }
            catch (IOException e)
            {
                throw new Exception(e.Message);
            }
        }

        public static void initializeSession(SessionState sessionState,
                                             uint sessionVersion,
                                             BobAxolotlParameters parameters)
        {

            try
            {
                sessionState.setSessionVersion(sessionVersion);
                sessionState.setRemoteIdentityKey(parameters.getTheirIdentityKey());
                sessionState.setLocalIdentityKey(parameters.getOurIdentityKey().getPublicKey());

                MemoryStream secrets = new MemoryStream();

                if (sessionVersion >= 3)
                {
                    byte[] discontinuityBytes = getDiscontinuityBytes();
                    secrets.Write(discontinuityBytes, 0, discontinuityBytes.Length);
                }

                byte[] agree1 = Curve.calculateAgreement(parameters.getTheirIdentityKey().getPublicKey(),
                                                       parameters.getOurSignedPreKey().getPrivateKey());
                byte[] agree2 = Curve.calculateAgreement(parameters.getTheirBaseKey(),
                                                       parameters.getOurIdentityKey().getPrivateKey());
                byte[] agree3 = Curve.calculateAgreement(parameters.getTheirBaseKey(),
                                                       parameters.getOurSignedPreKey().getPrivateKey());
                secrets.Write(agree1, 0, agree1.Length);
                secrets.Write(agree2, 0, agree2.Length);
                secrets.Write(agree3, 0, agree3.Length);

                if (sessionVersion >= 3 && parameters.getOurOneTimePreKey().HasValue)
                {
                    byte[] agree4 = Curve.calculateAgreement(parameters.getTheirBaseKey(),
                                                           parameters.getOurOneTimePreKey().ForceGetValue().getPrivateKey());
                    secrets.Write(agree4, 0, agree4.Length);
                }

                DerivedKeys derivedKeys = calculateDerivedKeys(sessionVersion, secrets.ToArray());

                sessionState.setSenderChain(parameters.getOurRatchetKey(), derivedKeys.getChainKey());
                sessionState.setRootKey(derivedKeys.getRootKey());
            }
            catch (IOException e)
            {
                throw new Exception(e.Message);
            }
        }

        private static byte[] getDiscontinuityBytes()
        {
            byte[] discontinuity = new byte[32];
            //Arrays.fill(discontinuity, (byte)0xFF);
            for (int i = 0; i < discontinuity.Length; i++)
            {
                discontinuity[i] = 0xFF;
            }
            return discontinuity;
        }

        private static DerivedKeys calculateDerivedKeys(uint sessionVersion, byte[] masterSecret)
        {
            HKDF kdf = HKDF.createFor(sessionVersion);
            byte[] derivedSecretBytes = kdf.deriveSecrets(masterSecret, Encoding.UTF8.GetBytes("WhisperText"), 64);
            byte[][] derivedSecrets = ByteUtil.split(derivedSecretBytes, 32, 32);

            return new DerivedKeys(new RootKey(kdf, derivedSecrets[0]),
                                   new ChainKey(kdf, derivedSecrets[1], 0));
        }

        private static bool isAlice(ECPublicKey ourKey, ECPublicKey theirKey)
        {
            return ourKey.CompareTo(theirKey) < 0;
        }

        public class DerivedKeys
        {
            private readonly RootKey rootKey;
            private readonly ChainKey chainKey;

            internal DerivedKeys(RootKey rootKey, ChainKey chainKey)
            {
                this.rootKey = rootKey;
                this.chainKey = chainKey;
            }

            public RootKey getRootKey()
            {
                return rootKey;
            }

            public ChainKey getChainKey()
            {
                return chainKey;
            }
        }
    }
}
