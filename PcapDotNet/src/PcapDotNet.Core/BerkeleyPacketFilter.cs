using System;
using System.Runtime.InteropServices;
using PcapDotNet.Core.Native;
using PcapDotNet.Packets;

namespace PcapDotNet.Core
{
    /// <summary>
    /// A packet filter, converting a high level filtering expression (see <see href="http://www.winpcap.org/docs/docs_40_2/html/group__language.html">WinPcap Filtering expression syntax</see>) in a program that can be interpreted by the kernel-level filtering engine. 
    /// The user must dispose instances of this class to deallocate resources.
    /// </summary>
    public sealed class BerkeleyPacketFilter : IDisposable
    {
        private IntPtr /* bpf_program* */ _bpf = IntPtr.Zero;

        /// <summary>
        /// Compile a packet filter without the need of opening an adapter. 
        /// This constructor converts a high level filtering expression (see <see href="http://www.winpcap.org/docs/docs_40_2/html/group__language.html">WinPcap Filtering expression syntax</see>) in a program that can be interpreted by the kernel-level filtering engine. 
        /// </summary>
        /// <param name="filterValue">A high level filtering expression (see <see href="http://www.winpcap.org/docs/docs_40_2/html/group__language.html">WinPcap Filtering expression syntax</see>)</param>
        /// <param name="snapshotLength">Length of the packet that has to be retained of the communicator this filter will be applied on.</param>
        /// <param name="kind">The link layer of an adapter that this filter will apply upon.</param>
        /// <param name="netmask">Specifies the IPv4 netmask of the network on which packets are being captured; it is used only when checking for IPv4 broadcast addresses in the filter program. If the netmask of the network on which packets are being captured isn't known to the program, or if packets are being captured on the Linux "any" pseudo-interface that can capture on more than one network, null can be supplied; tests for IPv4 broadcast addreses won't be done correctly, but all other tests in the filter program will be OK.</param>
        /// <exception cref="ArgumentException">Indicates an error. Probably caused by bad syntax.</exception>
        /// <remarks>
        /// If the purpose of this filter is to apply it on a communicator and not to test packets in memory, it would be simpler to call to PacketCommunicator.CreateFilter() or to directly call PacketCommunicator.SetFilter().
        /// </remarks>
        public BerkeleyPacketFilter(string filterValue, int snapshotLength, DataLinkKind kind, IpV4SocketAddress netmask)
        {
            Initialize(filterValue, snapshotLength, kind, netmask);
        }

        /// <summary>
        /// Compile a packet filter without the need of opening an adapter. 
        /// This constructor converts a high level filtering expression (see <see href="http://www.winpcap.org/docs/docs_40_2/html/group__language.html">WinPcap Filtering expression syntax</see>) in a program that can be interpreted by the kernel-level filtering engine. 
        /// Assumes the netmask of the network on which packets are being captured isn't known to the program, or that packets are being captured on the Linux "any" pseudo-interface that can capture on more than one network.
        /// Tests for IPv4 broadcast addreses won't be done correctly, but all other tests in the filter program will be OK.
        /// </summary>
        /// <param name="filterValue">A high level filtering expression (see <see href="http://www.winpcap.org/docs/docs_40_2/html/group__language.html">WinPcap Filtering expression syntax</see>)</param>
        /// <param name="snapshotLength">Length of the packet that has to be retained of the communicator this filter will be applied on.</param>
        /// <param name="kind">The link layer of an adapter that this filter will apply upon.</param>
        /// <exception cref="ArgumentException">Indicates an error. Probably caused by bad syntax.</exception>
        /// <remarks>
        /// If the purpose of this filter is to apply it on a communicator and not to test packets in memory, it would be simpler to call to PacketCommunicator.CreateFilter() or to directly call PacketCommunicator.SetFilter().
        /// </remarks>
        public BerkeleyPacketFilter(string filterValue, int snapshotLength, DataLinkKind kind)
        {
            Initialize(filterValue, snapshotLength, kind, null);
        }

        internal BerkeleyPacketFilter(PcapHandle /* pcap_t* */ pcapDescriptor, string filterString, IpV4SocketAddress netmask)
        {
            Initialize(pcapDescriptor, filterString, netmask);
        }

        /// <summary>
        /// Free a filter.
        /// Used to free up allocated memory when that BPF program is no longer needed, for example after it has been made the filter program for a packet communicator by a call to PacketCommunicator.SetFilter().
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        ~BerkeleyPacketFilter()
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
        { 
            Dispose(false); 
        }

        /// <summary>
        /// Returns if a given filter applies to an offline packet.
        /// This method is used to apply a filter to a packet that is currently in memory.
        /// This process does not need to open an adapter; we need just to create the proper filter (by settings parameters like the snapshot length, or the link-layer type) by means of the Pcap.
        /// The current API of libpcap does not allow to receive a packet and to filter the packet after it has been received. However, this can be useful in case you want to filter packets in the application, instead of into the receiving process. This function allows you to do the job.
        /// </summary>
        /// <param name="snapshotLength">The length of the bytes that are currently available into the packet if the packet satisfies the filter, 0 otherwise.</param>
        /// <param name="packet">The packet that has to be filtered.</param>
        /// <returns>
        /// True if the given packet satisfies the filter.
        /// </returns>
        public bool Test(out int snapshotLength, Packet packet)
        {
            if (packet == null)
                throw new ArgumentNullException(nameof(packet));

            using (var header = new PcapPacketHeaderHandle(packet))
            {
                unsafe
                {
                    fixed (byte* data = packet.Buffer)
                    {
                        snapshotLength = Interop.Pcap.pcap_offline_filter(_bpf, header.Pointer, (IntPtr)data);
                        return (snapshotLength != 0);
                    }
                }
            }
        }

        /// <summary>
        /// Returns if a given filter applies to an offline packet.
        /// This method is used to apply a filter to a packet that is currently in memory. 
        /// This process does not need to open an adapter; we need just to create the proper filter (by settings parameters like the snapshot length, or the link-layer type) by means of the Pcap.
        /// The current API of libpcap does not allow to receive a packet and to filter the packet after it has been received. However, this can be useful in case you want to filter packets in the application, instead of into the receiving process. This function allows you to do the job.
        /// </summary>
        /// <param name="packet">The packet that has to be filtered.</param>
        /// <returns>
        /// True if the given packet satisfies the filter.
        /// </returns>
        public bool Test(Packet packet)
        {
            return Test(out _, packet);
        }

        internal void SetFilter(PcapHandle /* pcap_t* */ pcapDescriptor)
        {
            if (Interop.Pcap.pcap_setfilter(pcapDescriptor, _bpf) != 0)
                PcapError.ThrowInvalidOperation("Failed setting bpf filter", pcapDescriptor);
        }

        private void Initialize(string filterString, int snapshotLength, DataLinkKind kind, IpV4SocketAddress netmask)
        {
            var dataLink = new PcapDataLink(kind);
            using (var pcapDescriptor = Interop.Pcap.pcap_open_dead(dataLink.Value, snapshotLength))
            {
                Initialize(pcapDescriptor, filterString, netmask);
            }
        }

        private void Initialize(PcapHandle /* pcap_t* */ pcapDescriptor, string filterString, IpV4SocketAddress netmask)
        {
            uint netmaskValue = 0;
            if (netmask != null)
                netmaskValue = netmask.Address.ToValue();

            _bpf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PcapUnmanagedStructures.bpf_program)));
            try
            {
                if (Interop.Pcap.pcap_compile(pcapDescriptor, _bpf, filterString, 1, netmaskValue) != 0)
                {
                    throw new ArgumentException("An error has occurred when compiling the filter <" + filterString + ">: " + PcapError.GetErrorMessage(pcapDescriptor));
                }
            }
            catch
            {
                Marshal.FreeHGlobal(_bpf);
                _bpf = IntPtr.Zero;
                throw;
            }
        }

        private void Dispose(bool disposing)
        {
            if (_bpf == IntPtr.Zero)
            {
                return;
            }

            if (disposing) { /* no managed resources here */ }

            Interop.Pcap.pcap_freecode(_bpf);
            Marshal.FreeHGlobal(_bpf);
            _bpf = IntPtr.Zero;
        }

    }
}
