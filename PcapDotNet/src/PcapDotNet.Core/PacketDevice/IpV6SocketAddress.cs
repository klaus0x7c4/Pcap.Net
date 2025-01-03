using System;
using System.Runtime.InteropServices;
using System.Text;
using PcapDotNet.Base;
using PcapDotNet.Core.Native;
using PcapDotNet.Packets.IpV6;
using UInt128 = PcapDotNet.Base.UInt128;

namespace PcapDotNet.Core
{
    /// <summary>
    /// An internet protocol version 6 address for a device.
    /// </summary>
    public sealed class IpV6SocketAddress : SocketAddress
    {
        private readonly IpV6Address _address;

        internal IpV6SocketAddress(IntPtr /* sockaddr* */ address) :
            base(SocketAddressFamily.Internet6)
        {
            if (address == IntPtr.Zero)
                throw new ArgumentNullException(nameof(address));

            var sockaddr_in6 = (PcapUnmanagedStructures.sockaddr_in6)Marshal.PtrToStructure(address, typeof(PcapUnmanagedStructures.sockaddr_in6));
            var byteValue = sockaddr_in6.sin6_addr;
            UInt128 value128 = BitSequence.Merge(byteValue[0], byteValue[1], byteValue[2], byteValue[3],
                                          byteValue[4], byteValue[5], byteValue[6], byteValue[7],
                                          byteValue[8], byteValue[9], byteValue[10], byteValue[11],
                                          byteValue[12], byteValue[13], byteValue[14], byteValue[15]);
            _address = new IpV6Address(value128);
        }

        /// <summary>
        /// The ip version 6 address.
        /// </summary>
        public IpV6Address Address => _address;

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
