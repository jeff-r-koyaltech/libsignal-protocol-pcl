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

using libaxolotl;
using libaxolotl.state;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace libaxolotl.state.impl
{
	public class InMemorySessionStore : SessionStore
	{

		static object Lock = new object();

		private IDictionary<AxolotlAddress, byte[]> sessions = new Dictionary<AxolotlAddress, byte[]>();

		public InMemorySessionStore() { }

		//[MethodImpl(MethodImplOptions.Synchronized)]
		public SessionRecord LoadSession(AxolotlAddress remoteAddress)
		{
			try
			{
				if (ContainsSession(remoteAddress))
				{
					byte[] session;
					sessions.TryGetValue(remoteAddress, out session); // get()

					return new SessionRecord(session);
				}
				else
				{
					return new SessionRecord();
				}
			}
			catch (Exception e)
			{
				throw new Exception(e.Message);
			}
		}


		public List<uint> GetSubDeviceSessions(String name)
		{
			List<uint> deviceIds = new List<uint>();

			foreach (AxolotlAddress key in sessions.Keys) //keySet()
			{
				if (key.getName().Equals(name) &&
					key.getDeviceId() != 1)
				{
					deviceIds.Add(key.getDeviceId());
				}
			}

			return deviceIds;
		}


		public void StoreSession(AxolotlAddress address, SessionRecord record)
		{
			sessions[address] = record.serialize();
		}


		public bool ContainsSession(AxolotlAddress address)
		{
			return sessions.ContainsKey(address);
		}


		public void DeleteSession(AxolotlAddress address)
		{
			sessions.Remove(address);
		}


		public void DeleteAllSessions(String name)
		{
			foreach (AxolotlAddress key in sessions.Keys) // keySet()
			{
				if (key.getName().Equals(name))
				{
					sessions.Remove(key);
				}
			}
		}
	}
}
