/** 
 * Copyright (C) 2015 smndtrl, langboost
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

using Google.ProtocolBuffers;
using libaxolotl.ecc;
using libaxolotl.kdf;
using libaxolotl.ratchet;
using libaxolotl.util;
using Strilanc.Value;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static libaxolotl.state.StorageProtos;
using static libaxolotl.state.StorageProtos.SessionStructure.Types;

namespace libaxolotl.state
{
	public class SessionState
	{
		private static readonly int MAX_MESSAGE_KEYS = 2000;

		private SessionStructure sessionStructure;

		public SessionState()
		{
			this.sessionStructure = SessionStructure.CreateBuilder().Build();
		}

		public SessionState(SessionStructure sessionStructure)
		{
			this.sessionStructure = sessionStructure;
		}

		public SessionState(SessionState copy)
		{
			this.sessionStructure = copy.sessionStructure.ToBuilder().Build();
		}

		public SessionStructure getStructure()
		{
			return sessionStructure;
		}

		public byte[] getAliceBaseKey()
		{
			return this.sessionStructure.AliceBaseKey.ToByteArray();
		}

		public void setAliceBaseKey(byte[] aliceBaseKey)
		{
			this.sessionStructure = this.sessionStructure.ToBuilder()
														 .SetAliceBaseKey(ByteString.CopyFrom(aliceBaseKey))
														 .Build();
		}

		public void setSessionVersion(uint version)
		{
			this.sessionStructure = this.sessionStructure.ToBuilder()
														 .SetSessionVersion(version)
														 .Build();
		}

		public uint getSessionVersion()
		{
			uint sessionVersion = this.sessionStructure.SessionVersion;

			if (sessionVersion == 0) return 2;
			else return sessionVersion;
		}

		public void setRemoteIdentityKey(IdentityKey identityKey)
		{
			this.sessionStructure = this.sessionStructure.ToBuilder()
														 .SetRemoteIdentityPublic(ByteString.CopyFrom(identityKey.serialize()))
														 .Build();
		}

		public void setLocalIdentityKey(IdentityKey identityKey)
		{
			this.sessionStructure = this.sessionStructure.ToBuilder()
														 .SetLocalIdentityPublic(ByteString.CopyFrom(identityKey.serialize()))
														 .Build();
		}

		public IdentityKey getRemoteIdentityKey()
		{
			try
			{
				if (!this.sessionStructure.HasRemoteIdentityPublic)
				{
					return null;
				}

				return new IdentityKey(this.sessionStructure.RemoteIdentityPublic.ToByteArray(), 0);
			}
			catch (InvalidKeyException e)
			{
				Debug.WriteLine(e.ToString(), "SessionRecordV2");
				return null;
			}
		}

		public IdentityKey getLocalIdentityKey()
		{
			try
			{
				return new IdentityKey(this.sessionStructure.LocalIdentityPublic.ToByteArray(), 0);
			}
			catch (InvalidKeyException e)
			{
				throw new Exception(e.Message);
			}
		}

		public uint getPreviousCounter()
		{
			return sessionStructure.PreviousCounter;
		}

		public void setPreviousCounter(uint previousCounter)
		{
			this.sessionStructure = this.sessionStructure.ToBuilder()
														 .SetPreviousCounter(previousCounter)
														 .Build();
		}

		public RootKey getRootKey()
		{
			return new RootKey(HKDF.createFor(getSessionVersion()),
							   this.sessionStructure.RootKey.ToByteArray());
		}

		public void setRootKey(RootKey rootKey)
		{
			this.sessionStructure = this.sessionStructure.ToBuilder()
														 .SetRootKey(ByteString.CopyFrom(rootKey.getKeyBytes()))
														 .Build();
		}

		public ECPublicKey getSenderRatchetKey()
		{
			try
			{
				return Curve.decodePoint(sessionStructure.SenderChain.SenderRatchetKey.ToByteArray(), 0);
			}
			catch (InvalidKeyException e)
			{
				throw new Exception(e.Message);
			}
		}

		public ECKeyPair getSenderRatchetKeyPair()
		{
			ECPublicKey publicKey = getSenderRatchetKey();
			ECPrivateKey privateKey = Curve.decodePrivatePoint(sessionStructure.SenderChain
																			   .SenderRatchetKeyPrivate
																			   .ToByteArray());

			return new ECKeyPair(publicKey, privateKey);
		}

		public bool hasReceiverChain(ECPublicKey senderEphemeral)
		{
			return getReceiverChain(senderEphemeral) != null;
		}

		public bool hasSenderChain()
		{
			return sessionStructure.HasSenderChain;
		}

		private Pair<Chain, uint> getReceiverChain(ECPublicKey senderEphemeral)
		{
			IList<Chain> receiverChains = sessionStructure.ReceiverChainsList;
			uint index = 0;

			foreach (Chain receiverChain in receiverChains)
			{
				try
				{
					ECPublicKey chainSenderRatchetKey = Curve.decodePoint(receiverChain.SenderRatchetKey.ToByteArray(), 0);

					if (chainSenderRatchetKey.Equals(senderEphemeral))
					{
						return new Pair<Chain, uint>(receiverChain, index);
					}
				}
				catch (InvalidKeyException e)
				{
					Debug.WriteLine(e.ToString(), "SessionRecordV2");
				}

				index++;
			}

			return null;
		}

		public ChainKey getReceiverChainKey(ECPublicKey senderEphemeral)
		{
			Pair<Chain, uint> receiverChainAndIndex = getReceiverChain(senderEphemeral);
			Chain receiverChain = receiverChainAndIndex.first();

			if (receiverChain == null)
			{
				return null;
			}
			else
			{
				return new ChainKey(HKDF.createFor(getSessionVersion()),
									receiverChain.ChainKey.Key.ToByteArray(),
									receiverChain.ChainKey.Index);
			}
		}

		public void addReceiverChain(ECPublicKey senderRatchetKey, ChainKey chainKey)
		{
			Chain.Types.ChainKey chainKeyStructure = Chain.Types.ChainKey.CreateBuilder()
															 .SetKey(ByteString.CopyFrom(chainKey.getKey()))
															 .SetIndex(chainKey.getIndex())
															 .Build();

			Chain chain = Chain.CreateBuilder()
							   .SetChainKey(chainKeyStructure)
							   .SetSenderRatchetKey(ByteString.CopyFrom(senderRatchetKey.serialize()))
							   .Build();

			this.sessionStructure = this.sessionStructure.ToBuilder().AddReceiverChains(chain).Build();

			if (this.sessionStructure.ReceiverChainsList.Count > 5)
			{
				this.sessionStructure = this.sessionStructure.ToBuilder()/*.ClearReceiverChains()*/.Build(); //RemoveReceiverChains(0) TODO: why does it work without
			}
		}

		public void setSenderChain(ECKeyPair senderRatchetKeyPair, ChainKey chainKey)
		{
			Chain.Types.ChainKey chainKeyStructure = Chain.Types.ChainKey.CreateBuilder()
															 .SetKey(ByteString.CopyFrom(chainKey.getKey()))
															 .SetIndex(chainKey.getIndex())
															 .Build();

			Chain senderChain = Chain.CreateBuilder()
									 .SetSenderRatchetKey(ByteString.CopyFrom(senderRatchetKeyPair.getPublicKey().serialize()))
									 .SetSenderRatchetKeyPrivate(ByteString.CopyFrom(senderRatchetKeyPair.getPrivateKey().serialize()))
									 .SetChainKey(chainKeyStructure)
									 .Build();

			this.sessionStructure = this.sessionStructure.ToBuilder().SetSenderChain(senderChain).Build();
		}

		public ChainKey getSenderChainKey()
		{
			Chain.Types.ChainKey chainKeyStructure = sessionStructure.SenderChain.ChainKey;
			return new ChainKey(HKDF.createFor(getSessionVersion()),
								chainKeyStructure.Key.ToByteArray(), chainKeyStructure.Index);
		}


		public void setSenderChainKey(ChainKey nextChainKey)
		{
			Chain.Types.ChainKey chainKey = Chain.Types.ChainKey.CreateBuilder()
													.SetKey(ByteString.CopyFrom(nextChainKey.getKey()))
													.SetIndex(nextChainKey.getIndex())
													.Build();

			Chain chain = sessionStructure.SenderChain.ToBuilder()
										  .SetChainKey(chainKey).Build();

			this.sessionStructure = this.sessionStructure.ToBuilder().SetSenderChain(chain).Build();
		}

		public bool hasMessageKeys(ECPublicKey senderEphemeral, uint counter)
		{
			Pair<Chain, uint> chainAndIndex = getReceiverChain(senderEphemeral);
			Chain chain = chainAndIndex.first();

			if (chain == null)
			{
				return false;
			}

			IList<Chain.Types.MessageKey> messageKeyList = chain.MessageKeysList;

			foreach (Chain.Types.MessageKey messageKey in messageKeyList)
			{
				if (messageKey.Index == counter)
				{
					return true;
				}
			}

			return false;
		}

		public MessageKeys removeMessageKeys(ECPublicKey senderEphemeral, uint counter)
		{
			Pair<Chain, uint> chainAndIndex = getReceiverChain(senderEphemeral);
			Chain chain = chainAndIndex.first();

			if (chain == null)
			{
				return null;
			}

			List<Chain.Types.MessageKey> messageKeyList = new List<Chain.Types.MessageKey>(chain.MessageKeysList);
			IEnumerator<Chain.Types.MessageKey> messageKeyIterator = messageKeyList.GetEnumerator();
			MessageKeys result = null;

			while (messageKeyIterator.MoveNext()) //hasNext()
			{
				Chain.Types.MessageKey messageKey = messageKeyIterator.Current; // next()

				if (messageKey.Index == counter)
				{
					result = new MessageKeys(messageKey.CipherKey.ToByteArray(),
											messageKey.MacKey.ToByteArray(),
											 messageKey.Iv.ToByteArray(),
											 messageKey.Index);

					messageKeyList.Remove(messageKey); //messageKeyIterator.remove();
					break;
				}
			}

			Chain updatedChain = chain.ToBuilder().ClearMessageKeys()
									  .AddRangeMessageKeys(messageKeyList) // AddAllMessageKeys
									  .Build();

			this.sessionStructure = this.sessionStructure.ToBuilder()
														 .SetReceiverChains((int)chainAndIndex.second(), updatedChain) // TODO: conv
														 .Build();

			return result;
		}

		public void setMessageKeys(ECPublicKey senderEphemeral, MessageKeys messageKeys)
		{
			Pair<Chain, uint> chainAndIndex = getReceiverChain(senderEphemeral);
			Chain chain = chainAndIndex.first();
			Chain.Types.MessageKey messageKeyStructure = Chain.Types.MessageKey.CreateBuilder()
																	  .SetCipherKey(ByteString.CopyFrom(messageKeys.getCipherKey()/*.getEncoded()*/))
																	  .SetMacKey(ByteString.CopyFrom(messageKeys.getMacKey()/*.getEncoded()*/))
																	  .SetIndex(messageKeys.getCounter())
																	  .SetIv(ByteString.CopyFrom(messageKeys.getIv()/*.getIV()*/))
																	  .Build();

			Chain.Builder updatedChain = chain.ToBuilder().AddMessageKeys(messageKeyStructure);
			if (updatedChain.MessageKeysList.Count > MAX_MESSAGE_KEYS)
			{
				updatedChain.MessageKeysList.RemoveAt(0);
			}

			this.sessionStructure = this.sessionStructure.ToBuilder()
														 .SetReceiverChains((int)chainAndIndex.second(), updatedChain.Build()) // TODO: conv
														 .Build();
		}

		public void setReceiverChainKey(ECPublicKey senderEphemeral, ChainKey chainKey)
		{
			Pair<Chain, uint> chainAndIndex = getReceiverChain(senderEphemeral);
			Chain chain = chainAndIndex.first();

			Chain.Types.ChainKey chainKeyStructure = Chain.Types.ChainKey.CreateBuilder()
															 .SetKey(ByteString.CopyFrom(chainKey.getKey()))
															 .SetIndex(chainKey.getIndex())
															 .Build();

			Chain updatedChain = chain.ToBuilder().SetChainKey(chainKeyStructure).Build();

			this.sessionStructure = this.sessionStructure.ToBuilder()
														 .SetReceiverChains((int)chainAndIndex.second(), updatedChain) // TODO: conv
														 .Build();
		}

		public void setPendingKeyExchange(uint sequence,
										  ECKeyPair ourBaseKey,
										  ECKeyPair ourRatchetKey,
										  IdentityKeyPair ourIdentityKey)
		{
			PendingKeyExchange structure =
				PendingKeyExchange.CreateBuilder()
								  .SetSequence(sequence)
								  .SetLocalBaseKey(ByteString.CopyFrom(ourBaseKey.getPublicKey().serialize()))
								  .SetLocalBaseKeyPrivate(ByteString.CopyFrom(ourBaseKey.getPrivateKey().serialize()))
								  .SetLocalRatchetKey(ByteString.CopyFrom(ourRatchetKey.getPublicKey().serialize()))
								  .SetLocalRatchetKeyPrivate(ByteString.CopyFrom(ourRatchetKey.getPrivateKey().serialize()))
								  .SetLocalIdentityKey(ByteString.CopyFrom(ourIdentityKey.getPublicKey().serialize()))
								  .SetLocalIdentityKeyPrivate(ByteString.CopyFrom(ourIdentityKey.getPrivateKey().serialize()))
								  .Build();

			this.sessionStructure = this.sessionStructure.ToBuilder()
														 .SetPendingKeyExchange(structure)
														 .Build();
		}

		public uint getPendingKeyExchangeSequence()
		{
			return sessionStructure.PendingKeyExchange.Sequence;
		}

		public ECKeyPair getPendingKeyExchangeBaseKey()
		{
			ECPublicKey publicKey = Curve.decodePoint(sessionStructure.PendingKeyExchange
																.LocalBaseKey.ToByteArray(), 0);

			ECPrivateKey privateKey = Curve.decodePrivatePoint(sessionStructure.PendingKeyExchange
																	   .LocalBaseKeyPrivate
																	   .ToByteArray());

			return new ECKeyPair(publicKey, privateKey);
		}

		public ECKeyPair getPendingKeyExchangeRatchetKey()
		{
			ECPublicKey publicKey = Curve.decodePoint(sessionStructure.PendingKeyExchange
																.LocalRatchetKey.ToByteArray(), 0);

			ECPrivateKey privateKey = Curve.decodePrivatePoint(sessionStructure.PendingKeyExchange
																	   .LocalRatchetKeyPrivate
																	   .ToByteArray());

			return new ECKeyPair(publicKey, privateKey);
		}

		public IdentityKeyPair getPendingKeyExchangeIdentityKey()
		{
			IdentityKey publicKey = new IdentityKey(sessionStructure.PendingKeyExchange
															.LocalIdentityKey.ToByteArray(), 0);

			ECPrivateKey privateKey = Curve.decodePrivatePoint(sessionStructure.PendingKeyExchange
																	   .LocalIdentityKeyPrivate
																	   .ToByteArray());

			return new IdentityKeyPair(publicKey, privateKey);
		}

		public bool hasPendingKeyExchange()
		{
			return sessionStructure.HasPendingKeyExchange;
		}

		public void setUnacknowledgedPreKeyMessage(May<uint> preKeyId, uint signedPreKeyId, ECPublicKey baseKey)
		{
			PendingPreKey.Builder pending = PendingPreKey.CreateBuilder()
														 .SetSignedPreKeyId(signedPreKeyId)
														 .SetBaseKey(ByteString.CopyFrom(baseKey.serialize()));

			if (preKeyId.HasValue)
			{
				pending.SetPreKeyId(preKeyId.ForceGetValue());
			}

			this.sessionStructure = this.sessionStructure.ToBuilder()
														 .SetPendingPreKey(pending.Build())
														 .Build();
		}

		public bool hasUnacknowledgedPreKeyMessage()
		{
			return this.sessionStructure.HasPendingPreKey;
		}

		public UnacknowledgedPreKeyMessageItems getUnacknowledgedPreKeyMessageItems()
		{
			try
			{
				May<uint> preKeyId;

				if (sessionStructure.PendingPreKey.HasPreKeyId)
				{
					preKeyId = new May<uint>(sessionStructure.PendingPreKey.PreKeyId);
				}
				else
				{
					preKeyId = May<uint>.NoValue;
				}

				return
					new UnacknowledgedPreKeyMessageItems(preKeyId,
														 sessionStructure.PendingPreKey.SignedPreKeyId,
														 Curve.decodePoint(sessionStructure.PendingPreKey
																						   .BaseKey
																						   .ToByteArray(), 0));
			}
			catch (InvalidKeyException e)
			{
				throw new Exception(e.Message);
			}
		}

		public void clearUnacknowledgedPreKeyMessage()
		{
			this.sessionStructure = this.sessionStructure.ToBuilder()
														 .ClearPendingPreKey()
														 .Build();
		}

		public void setRemoteRegistrationId(uint registrationId)
		{
			this.sessionStructure = this.sessionStructure.ToBuilder()
														 .SetRemoteRegistrationId(registrationId)
														 .Build();
		}

		public uint getRemoteRegistrationId()
		{
			return this.sessionStructure.RemoteRegistrationId;
		}

		public void setLocalRegistrationId(uint registrationId)
		{
			this.sessionStructure = this.sessionStructure.ToBuilder()
														 .SetLocalRegistrationId(registrationId)
														 .Build();
		}

		public uint GetLocalRegistrationId()
		{
			return this.sessionStructure.LocalRegistrationId;
		}

		public byte[] serialize()
		{
			return sessionStructure.ToByteArray();
		}

		public class UnacknowledgedPreKeyMessageItems
		{
			private readonly May<uint> preKeyId;
			private readonly uint signedPreKeyId;
			private readonly ECPublicKey baseKey;

			public UnacknowledgedPreKeyMessageItems(May<uint> preKeyId,
													uint signedPreKeyId,
													ECPublicKey baseKey)
			{
				this.preKeyId = preKeyId;
				this.signedPreKeyId = signedPreKeyId;
				this.baseKey = baseKey;
			}


			public May<uint> getPreKeyId()
			{
				return preKeyId;
			}

			public uint getSignedPreKeyId()
			{
				return signedPreKeyId;
			}

			public ECPublicKey getBaseKey()
			{
				return baseKey;
			}
		}
	}
}
