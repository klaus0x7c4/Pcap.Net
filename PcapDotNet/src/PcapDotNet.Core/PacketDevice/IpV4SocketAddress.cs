using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using PcapDotNet.Core.Native;
using PcapDotNet.Packets.IpV4;

namespace PcapDotNet.Core
{
    /// <summary>
    /// An internet protocol version 4 address for a device.
    /// </summary>
    public sealed class IpV4SocketAddress  : SocketAddress
    {
        private readonly IpV4Address _address;

        internal IpV4SocketAddress(IntPtr /* sockaddr* */ address) :
            base(SocketAddressFamily.Internet)
        {
            if (address == IntPtr.Zero)
                throw new ArgumentNullException(nameof(address));

            var sockaddr_in = (PcapUnmanagedStructures.sockaddr_in)Marshal.PtrToStructure(address, typeof(PcapUnmanagedStructures.sockaddr_in));
            _address = new IpV4Address((uint)IPAddress.NetworkToHostOrder(unchecked((int)sockaddr_in.sin_addr.s_addr)));
        }

        /// <summary>
        /// The ip version 4 address.
        /// </summary>
        public IpV4Address Address => _address;
        
        /// <inheritdoc/>
        public override string ToString()
        {
            var result = new StringBuilder();
            result.Append(base.ToString());
            result.Append(" ");
            result.Append(Address);
            return result.ToString();
        }
    }
}
