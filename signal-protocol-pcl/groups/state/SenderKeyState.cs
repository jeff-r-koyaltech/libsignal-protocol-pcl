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
using libaxolotl.groups.ratchet;
using Strilanc.Value;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static libaxolotl.state.StorageProtos;

namespace libaxolotl.groups.state
{
	/**
     * Represents the state of an individual SenderKey ratchet.
     *
     * @author
     */
	public class SenderKeyState
	{
		private static readonly int MAX_MESSAGE_KEYS = 2000;

		private SenderKeyStateStructure senderKeyStateStructure;

		public SenderKeyState(uint id, uint iteration, byte[] chainKey, ECPublicKey signatureKey)
			: this(id, iteration, chainKey, signatureKey, May<ECPrivateKey>.NoValue)
		{
		}

		public SenderKeyState(uint id, uint iteration, byte[] chainKey, ECKeyPair signatureKey)
		: this(id, iteration, chainKey, signatureKey.getPublicKey(), new May<ECPrivateKey>(signatureKey.getPrivateKey()))
		{
		}

		private SenderKeyState(uint id, uint iteration, byte[] chainKey,
							  ECPublicKey signatureKeyPublic,
							  May<ECPrivateKey> signatureKeyPrivate)
		{
			SenderKeyStateStructure.Types.SenderChainKey senderChainKeyStructure =
				SenderKeyStateStructure.Types.SenderChainKey.CreateBuilder()
													  .SetIteration(iteration)
													  .SetSeed(ByteString.CopyFrom(chainKey))
													  .Build();

			SenderKeyStateStructure.Types.SenderSigningKey.Builder signingKeyStructure =
				SenderKeyStateStructure.Types.SenderSigningKey.CreateBuilder()
														.SetPublic(ByteString.CopyFrom(signatureKeyPublic.serialize()));

			if (signatureKeyPrivate.HasValue)
			{
				signingKeyStructure.SetPrivate(ByteString.CopyFrom(signatureKeyPrivate.ForceGetValue().serialize()));
			}

			this.senderKeyStateStructure = SenderKeyStateStructure.CreateBuilder()
																  .SetSenderKeyId(id)
																  .SetSenderChainKey(senderChainKeyStructure)
																  .SetSenderSigningKey(signingKeyStructure)
																  .Build();
		}

		public SenderKeyState(SenderKeyStateStructure senderKeyStateStructure)
		{
			this.senderKeyStateStructure = senderKeyStateStructure;
		}

		public uint getKeyId()
		{
			return senderKeyStateStructure.SenderKeyId;
		}

		public SenderChainKey getSenderChainKey()
		{
			return new SenderChainKey(senderKeyStateStructure.SenderChainKey.Iteration,
									  senderKeyStateStructure.SenderChainKey.Seed.ToByteArray());
		}

		public void setSenderChainKey(SenderChainKey chainKey)
		{
			SenderKeyStateStructure.Types.SenderChainKey senderChainKeyStructure =
				SenderKeyStateStructure.Types.SenderChainKey.CreateBuilder()
													  .SetIteration(chainKey.getIteration())
													  .SetSeed(ByteString.CopyFrom(chainKey.getSeed()))
													  .Build();

			this.senderKeyStateStructure = senderKeyStateStructure.ToBuilder()
																  .SetSenderChainKey(senderChainKeyStructure)
																  .Build();
		}

		public ECPublicKey getSigningKeyPublic()
		{
			return Curve.decodePoint(senderKeyStateStructure.SenderSigningKey.Public.ToByteArray(), 0);
		}

		public ECPrivateKey getSigningKeyPrivate()
		{
			return Curve.decodePrivatePoint(senderKeyStateStructure.SenderSigningKey.Private.ToByteArray());
		}

		public bool hasSenderMessageKey(uint iteration)
		{
			foreach (SenderKeyStateStructure.Types.SenderMessageKey senderMessageKey in senderKeyStateStructure.SenderMessageKeysList)
			{
				if (senderMessageKey.Iteration == iteration) return true;
			}

			return false;
		}

		public void addSenderMessageKey(SenderMessageKey senderMessageKey)
		{
			SenderKeyStateStructure.Types.SenderMessageKey senderMessageKeyStructure =
				SenderKeyStateStructure.Types.SenderMessageKey.CreateBuilder()
														.SetIteration(senderMessageKey.getIteration())
														.SetSeed(ByteString.CopyFrom(senderMessageKey.getSeed()))
														.Build();

			SenderKeyStateStructure.Builder builder = this.senderKeyStateStructure.ToBuilder();
			builder.AddSenderMessageKeys(senderMessageKeyStructure);

			if (builder.SenderMessageKeysList.Count > MAX_MESSAGE_KEYS)
			{
				builder.SenderMessageKeysList.RemoveAt(0);
			}
			this.senderKeyStateStructure = builder.Build();
		}

		public SenderMessageKey removeSenderMessageKey(uint iteration)
		{
			LinkedList<SenderKeyStateStructure.Types.SenderMessageKey> keys = new LinkedList<SenderKeyStateStructure.Types.SenderMessageKey>(senderKeyStateStructure.SenderMessageKeysList);
			IEnumerator<SenderKeyStateStructure.Types.SenderMessageKey> iterator = keys.GetEnumerator(); // iterator();

			SenderKeyStateStructure.Types.SenderMessageKey result = null;

			while (iterator.MoveNext()) // hastNext
			{
				SenderKeyStateStructure.Types.SenderMessageKey senderMessageKey = iterator.Current; // next();

				if (senderMessageKey.Iteration == iteration) //senderMessageKey.getIteration()
				{
					result = senderMessageKey;
					keys.Remove(senderMessageKey); //iterator.remove();
					break;
				}
			}

			this.senderKeyStateStructure = this.senderKeyStateStructure.ToBuilder()
																	   .ClearSenderMessageKeys()
																	   //.AddAllSenderMessageKeys(keys)
																	   .AddRangeSenderMessageKeys(keys)
																	   .Build();

			if (result != null)
			{
				return new SenderMessageKey(result.Iteration, result.Seed.ToByteArray());
			}
			else
			{
				return null;
			}
		}

		public SenderKeyStateStructure getStructure()
		{
			return senderKeyStateStructure;
		}
	}
}
