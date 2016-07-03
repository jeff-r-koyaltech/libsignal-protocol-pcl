/** 
 * Copyright (C) 2016 smndtrl, langboost
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

using libsignal.ecc;
using libsignal.exceptions;
using libsignal.protocol;
using libsignal.ratchet;
using libsignal.state;
using libsignal.util;
using Strilanc.Value;
using System;
using System.Diagnostics;

namespace libsignal
{
    /**
 * SessionBuilder is responsible for setting up encrypted sessions.
 * Once a session has been established, {@link org.whispersystems.libsignal.SessionCipher}
 * can be used to encrypt/decrypt messages in that session.
 * <p>
 * Sessions are built from one of three different possible vectors:
 * <ol>
 *   <li>A {@link org.whispersystems.libsignal.state.PreKeyBundle} retrieved from a server.</li>
 *   <li>A {@link PreKeySignalMessage} received from a client.</li>
 *   <li>A {@link KeyExchangeMessage} sent to or received from a client.</li>
 * </ol>
 *
 * Sessions are constructed per recipientId + deviceId tuple.  Remote logical users are identified
 * by their recipientId, and each logical recipientId can have multiple physical devices.
 *
 * @author Moxie Marlinspike
 */
    public class SessionBuilder
    {

        private readonly SessionStore sessionStore;
        private readonly PreKeyStore preKeyStore;
        private readonly SignedPreKeyStore signedPreKeyStore;
        private readonly IdentityKeyStore identityKeyStore;
        private readonly SignalProtocolAddress remoteAddress;

        /**
         * Constructs a SessionBuilder.
         *
         * @param sessionStore The {@link org.whispersystems.libsignal.state.SessionStore} to store the constructed session in.
         * @param preKeyStore The {@link  org.whispersystems.libsignal.state.PreKeyStore} where the client's local {@link org.whispersystems.libsignal.state.PreKeyRecord}s are stored.
         * @param identityKeyStore The {@link org.whispersystems.libsignal.state.IdentityKeyStore} containing the client's identity key information.
         * @param remoteAddress The address of the remote user to build a session with.
         */
        public SessionBuilder(SessionStore sessionStore,
                              PreKeyStore preKeyStore,
                              SignedPreKeyStore signedPreKeyStore,
                              IdentityKeyStore identityKeyStore,
                              SignalProtocolAddress remoteAddress)
        {
            this.sessionStore = sessionStore;
            this.preKeyStore = preKeyStore;
            this.signedPreKeyStore = signedPreKeyStore;
            this.identityKeyStore = identityKeyStore;
            this.remoteAddress = remoteAddress;
        }

        /**
         * Constructs a SessionBuilder
         * @param store The {@link SignalProtocolStore} to store all state information in.
         * @param remoteAddress The address of the remote user to build a session with.
         */
        public SessionBuilder(SignalProtocolStore store, SignalProtocolAddress remoteAddress)
            : this(store, store, store, store, remoteAddress)
        {
        }

        /**
         * Build a new session from a received {@link PreKeySignalMessage}.
         *
         * After a session is constructed in this way, the embedded {@link SignalMessage}
         * can be decrypted.
         *
         * @param message The received {@link PreKeySignalMessage}.
         * @throws org.whispersystems.libsignal.InvalidKeyIdException when there is no local
         *                                                             {@link org.whispersystems.libsignal.state.PreKeyRecord}
         *                                                             that corresponds to the PreKey ID in
         *                                                             the message.
         * @throws org.whispersystems.libsignal.InvalidKeyException when the message is formatted incorrectly.
         * @throws org.whispersystems.libsignal.UntrustedIdentityException when the {@link IdentityKey} of the sender is untrusted.
         */
        /*package*/
        internal May<uint>  process(SessionRecord sessionRecord, PreKeySignalMessage message)
        {
            uint messageVersion = message.getMessageVersion();
            IdentityKey theirIdentityKey = message.getIdentityKey();

            if (!identityKeyStore.IsTrustedIdentity(remoteAddress.getName(), theirIdentityKey))
            {
                throw new UntrustedIdentityException(remoteAddress.getName(), theirIdentityKey);
            }

            May<uint> unsignedPreKeyId = processV3(sessionRecord, message);

            identityKeyStore.SaveIdentity(remoteAddress.getName(), theirIdentityKey);
            return unsignedPreKeyId;
        }

        private May<uint> processV3(SessionRecord sessionRecord, PreKeySignalMessage message)
        {

            if (sessionRecord.hasSessionState(message.getMessageVersion(), message.getBaseKey().serialize()))
            {
                Debug.WriteLine("We've already setup a session for this V3 message, letting bundled message fall through...");
                return May<uint>.NoValue;
            }

            ECKeyPair ourSignedPreKey = signedPreKeyStore.LoadSignedPreKey(message.getSignedPreKeyId()).getKeyPair();

            BobSignalProtocolParameters.Builder parameters = BobSignalProtocolParameters.newBuilder();

            parameters.setTheirBaseKey(message.getBaseKey())
                      .setTheirIdentityKey(message.getIdentityKey())
                      .setOurIdentityKey(identityKeyStore.GetIdentityKeyPair())
                      .setOurSignedPreKey(ourSignedPreKey)
                      .setOurRatchetKey(ourSignedPreKey);

            if (message.getPreKeyId().HasValue)
            {
                parameters.setOurOneTimePreKey(new May<ECKeyPair>(preKeyStore.LoadPreKey(message.getPreKeyId().ForceGetValue()).getKeyPair()));
            }
            else
            {
                parameters.setOurOneTimePreKey(May<ECKeyPair>.NoValue);
            }

            if (!sessionRecord.isFresh()) sessionRecord.archiveCurrentState();

            RatchetingSession.initializeSession(sessionRecord.getSessionState(), parameters.create());

            sessionRecord.getSessionState().setLocalRegistrationId(identityKeyStore.GetLocalRegistrationId());
            sessionRecord.getSessionState().setRemoteRegistrationId(message.getRegistrationId());
            sessionRecord.getSessionState().setAliceBaseKey(message.getBaseKey().serialize());

            if (message.getPreKeyId().HasValue && message.getPreKeyId().ForceGetValue() != Medium.MAX_VALUE)
            {
                return message.getPreKeyId();
            }
            else
            {
                return May<uint>.NoValue;
            }
        }

        /**
         * Build a new session from a {@link org.whispersystems.libsignal.state.PreKeyBundle} retrieved from
         * a server.
         *
         * @param preKey A PreKey for the destination recipient, retrieved from a server.
         * @throws InvalidKeyException when the {@link org.whispersystems.libsignal.state.PreKeyBundle} is
         *                             badly formatted.
         * @throws org.whispersystems.libsignal.UntrustedIdentityException when the sender's
         *                                                                  {@link IdentityKey} is not
         *                                                                  trusted.
         */
        public void process(PreKeyBundle preKey)
        {
            lock (SessionCipher.SESSION_LOCK)
            {
                if (!identityKeyStore.IsTrustedIdentity(remoteAddress.getName(), preKey.getIdentityKey()))
                {
                    throw new UntrustedIdentityException(remoteAddress.getName(), preKey.getIdentityKey());
                }

                if (preKey.getSignedPreKey() != null &&
                    !Curve.verifySignature(preKey.getIdentityKey().getPublicKey(),
                                           preKey.getSignedPreKey().serialize(),
                                           preKey.getSignedPreKeySignature()))
                {
                    throw new InvalidKeyException("Invalid signature on device key!");
                }

                if (preKey.getSignedPreKey() == null)
                {
                    throw new InvalidKeyException("No signed prekey!");
                }

                SessionRecord sessionRecord = sessionStore.LoadSession(remoteAddress);
                ECKeyPair ourBaseKey = Curve.generateKeyPair();
                ECPublicKey theirSignedPreKey = preKey.getSignedPreKey();
                ECPublicKey test = preKey.getPreKey();
                May<ECPublicKey> theirOneTimePreKey = (test == null) ? May<ECPublicKey>.NoValue : new May<ECPublicKey>(test);
                May<uint> theirOneTimePreKeyId = theirOneTimePreKey.HasValue ? new May<uint>(preKey.getPreKeyId()) :
                                                                                              May<uint>.NoValue;

                AliceSignalProtocolParameters.Builder parameters = AliceSignalProtocolParameters.newBuilder();

                parameters.setOurBaseKey(ourBaseKey)
                              .setOurIdentityKey(identityKeyStore.GetIdentityKeyPair())
                              .setTheirIdentityKey(preKey.getIdentityKey())
                              .setTheirSignedPreKey(theirSignedPreKey)
                              .setTheirRatchetKey(theirSignedPreKey)
                              .setTheirOneTimePreKey(theirOneTimePreKey);

                if (!sessionRecord.isFresh()) sessionRecord.archiveCurrentState();

                RatchetingSession.initializeSession(sessionRecord.getSessionState(), parameters.create());

                sessionRecord.getSessionState().setUnacknowledgedPreKeyMessage(theirOneTimePreKeyId, preKey.getSignedPreKeyId(), ourBaseKey.getPublicKey());
                sessionRecord.getSessionState().setLocalRegistrationId(identityKeyStore.GetLocalRegistrationId());
                sessionRecord.getSessionState().setRemoteRegistrationId(preKey.getRegistrationId());
                sessionRecord.getSessionState().setAliceBaseKey(ourBaseKey.getPublicKey().serialize());

                sessionStore.StoreSession(remoteAddress, sessionRecord);
                identityKeyStore.SaveIdentity(remoteAddress.getName(), preKey.getIdentityKey());
            }
        }

        /**
         * Build a new session from a {@link KeyExchangeMessage}
         * received from a remote client.
         *
         * @param message The received KeyExchangeMessage.
         * @return The KeyExchangeMessage to respond with, or null if no response is necessary.
         * @throws InvalidKeyException if the received KeyExchangeMessage is badly formatted.
         */
        public KeyExchangeMessage process(KeyExchangeMessage message)

        {
            lock (SessionCipher.SESSION_LOCK)
            {
                if (!identityKeyStore.IsTrustedIdentity(remoteAddress.getName(), message.getIdentityKey()))
                {
                    throw new UntrustedIdentityException(remoteAddress.getName(), message.getIdentityKey());
                }

                KeyExchangeMessage responseMessage = null;

                if (message.isInitiate()) responseMessage = processInitiate(message);
                else processResponse(message);

                return responseMessage;
            }
        }

        private KeyExchangeMessage processInitiate(KeyExchangeMessage message)
        {
            uint flags = KeyExchangeMessage.RESPONSE_FLAG;
            SessionRecord sessionRecord = sessionStore.LoadSession(remoteAddress);

            if (!Curve.verifySignature(message.getIdentityKey().getPublicKey(),
                                       message.getBaseKey().serialize(),
                                       message.getBaseKeySignature()))
            {
                throw new InvalidKeyException("Bad signature!");
            }

            SymmetricSignalProtocolParameters.Builder builder = SymmetricSignalProtocolParameters.newBuilder();

            if (!sessionRecord.getSessionState().hasPendingKeyExchange())
            {
                builder.setOurIdentityKey(identityKeyStore.GetIdentityKeyPair())
                       .setOurBaseKey(Curve.generateKeyPair())
                       .setOurRatchetKey(Curve.generateKeyPair());
            }
            else
            {
                builder.setOurIdentityKey(sessionRecord.getSessionState().getPendingKeyExchangeIdentityKey())
                       .setOurBaseKey(sessionRecord.getSessionState().getPendingKeyExchangeBaseKey())
                       .setOurRatchetKey(sessionRecord.getSessionState().getPendingKeyExchangeRatchetKey());
                flags |= KeyExchangeMessage.SIMULTAENOUS_INITIATE_FLAG;
            }

            builder.setTheirBaseKey(message.getBaseKey())
                   .setTheirRatchetKey(message.getRatchetKey())
                   .setTheirIdentityKey(message.getIdentityKey());

            SymmetricSignalProtocolParameters parameters = builder.create();

            if (!sessionRecord.isFresh()) sessionRecord.archiveCurrentState();

            RatchetingSession.initializeSession(sessionRecord.getSessionState(),
                                                parameters);

            sessionStore.StoreSession(remoteAddress, sessionRecord);
            identityKeyStore.SaveIdentity(remoteAddress.getName(), message.getIdentityKey());

            byte[] baseKeySignature = Curve.calculateSignature(parameters.getOurIdentityKey().getPrivateKey(),
                                                               parameters.getOurBaseKey().getPublicKey().serialize());

            return new KeyExchangeMessage(sessionRecord.getSessionState().getSessionVersion(),
                                          message.getSequence(), flags,
                                          parameters.getOurBaseKey().getPublicKey(),
                                          baseKeySignature, parameters.getOurRatchetKey().getPublicKey(),
                                          parameters.getOurIdentityKey().getPublicKey());
        }

        private void processResponse(KeyExchangeMessage message)
        {
            SessionRecord sessionRecord = sessionStore.LoadSession(remoteAddress);
            SessionState sessionState = sessionRecord.getSessionState();
            bool hasPendingKeyExchange = sessionState.hasPendingKeyExchange();
            bool isSimultaneousInitiateResponse = message.isResponseForSimultaneousInitiate();

            if (!hasPendingKeyExchange || sessionState.getPendingKeyExchangeSequence() != message.getSequence())
            {
                Debug.WriteLine("No matching sequence for response. Is simultaneous initiate response: " + isSimultaneousInitiateResponse);
                if (!isSimultaneousInitiateResponse) throw new StaleKeyExchangeException();
                else return;
            }

            SymmetricSignalProtocolParameters.Builder parameters = SymmetricSignalProtocolParameters.newBuilder();

            parameters.setOurBaseKey(sessionRecord.getSessionState().getPendingKeyExchangeBaseKey())
                      .setOurRatchetKey(sessionRecord.getSessionState().getPendingKeyExchangeRatchetKey())
                      .setOurIdentityKey(sessionRecord.getSessionState().getPendingKeyExchangeIdentityKey())
                      .setTheirBaseKey(message.getBaseKey())
                      .setTheirRatchetKey(message.getRatchetKey())
                      .setTheirIdentityKey(message.getIdentityKey());

            if (!sessionRecord.isFresh()) sessionRecord.archiveCurrentState();

            RatchetingSession.initializeSession(sessionRecord.getSessionState(), parameters.create());

            if (!Curve.verifySignature(message.getIdentityKey().getPublicKey(),
                                       message.getBaseKey().serialize(),
                                       message.getBaseKeySignature()))
            {
                throw new InvalidKeyException("Base key signature doesn't match!");
            }

            sessionStore.StoreSession(remoteAddress, sessionRecord);
            identityKeyStore.SaveIdentity(remoteAddress.getName(), message.getIdentityKey());

        }

        /**
         * Initiate a new session by sending an initial KeyExchangeMessage to the recipient.
         *
         * @return the KeyExchangeMessage to deliver.
         */
        public KeyExchangeMessage process()
        {
            lock (SessionCipher.SESSION_LOCK)
            {
                try
                {
                    uint sequence = KeyHelper.getRandomSequence(65534) + 1;
                    uint flags = KeyExchangeMessage.INITIATE_FLAG;
                    ECKeyPair baseKey = Curve.generateKeyPair();
                    ECKeyPair ratchetKey = Curve.generateKeyPair();
                    IdentityKeyPair identityKey = identityKeyStore.GetIdentityKeyPair();
                    byte[] baseKeySignature = Curve.calculateSignature(identityKey.getPrivateKey(), baseKey.getPublicKey().serialize());
                    SessionRecord sessionRecord = sessionStore.LoadSession(remoteAddress);

                    sessionRecord.getSessionState().setPendingKeyExchange(sequence, baseKey, ratchetKey, identityKey);
                    sessionStore.StoreSession(remoteAddress, sessionRecord);

                    return new KeyExchangeMessage(CiphertextMessage.CURRENT_VERSION, sequence, flags, baseKey.getPublicKey(), baseKeySignature,
                                                  ratchetKey.getPublicKey(), identityKey.getPublicKey());
                }
                catch (InvalidKeyException e)
                {
                    throw new Exception(e.Message);
                }
            }
        }


    }
}
