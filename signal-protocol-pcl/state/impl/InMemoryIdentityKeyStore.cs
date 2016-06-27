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

using System;
using System.Collections.Generic;

namespace libaxolotl.state.impl
{
	/// <summary>
	/// In-memory / testing implementation of IdentityKeyStore
	/// </summary>
	public class InMemoryIdentityKeyStore : IdentityKeyStore
	{

		private readonly IDictionary<String, IdentityKey> trustedKeys = new Dictionary<String, IdentityKey>();

		private readonly IdentityKeyPair identityKeyPair;
		private readonly uint localRegistrationId;

		/// <summary>
		/// .ctor
		/// </summary>
		public InMemoryIdentityKeyStore(IdentityKeyPair identityKeyPair, uint localRegistrationId)
		{
			this.identityKeyPair = identityKeyPair;
			this.localRegistrationId = localRegistrationId;
		}

		public IdentityKeyPair GetIdentityKeyPair()
		{
			return identityKeyPair;
		}


		public uint GetLocalRegistrationId()
		{
			return localRegistrationId;
		}

		public bool SaveIdentity(String name, IdentityKey identityKey)
		{
			trustedKeys[name] = identityKey; //put
			return true;
		}

		public bool IsTrustedIdentity(String name, IdentityKey identityKey)
		{
			IdentityKey trusted;
			trustedKeys.TryGetValue(name, out trusted); // get(name)
			return (trusted == null || trusted.Equals(identityKey));
		}
	}
}
