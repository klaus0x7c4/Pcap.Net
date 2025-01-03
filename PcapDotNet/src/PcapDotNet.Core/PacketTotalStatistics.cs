using System;
using System.Runtime.InteropServices;
using System.Text;
using PcapDotNet.Core.Native;

namespace PcapDotNet.Core
{
    /// <summary>
    /// Statistics on capture from the start of the run.
    /// </summary>
    public sealed class PacketTotalStatistics : IEquatable<PacketTotalStatistics>
    {
        private readonly uint _packetsReceived;
        private readonly uint _packetsDroppedByDriver;
        private readonly uint _packetsDroppedByInterface;
        private readonly uint _packetsCaptured;

        internal PacketTotalStatistics(PcapUnmanagedStructures.pcap_stat_unix stat)
        {
            _packetsReceived = (uint)stat.ps_recv.ToInt64();
            _packetsDroppedByDriver = (uint)stat.ps_drop.ToInt64();
            _packetsDroppedByInterface = (uint)stat.ps_ifdrop.ToInt64();
        }

        internal PacketTotalStatistics(IntPtr /* const pcap_stat&  */ statisticsPtr, int statisticsSize)
        {
            const int elementSize = sizeof(uint);

            _packetsReceived = (uint)Marshal.ReadInt32(statisticsPtr, 0 * elementSize);
            _packetsDroppedByDriver = (uint)Marshal.ReadInt32(statisticsPtr, 1 * elementSize);
            _packetsDroppedByInterface = (uint)Marshal.ReadInt32(statisticsPtr, 2 * elementSize);
            _packetsCaptured = statisticsSize >= 16
                        ? (uint)Marshal.ReadInt32(statisticsPtr, 3 * elementSize)
                        : 0;
        }

        /// <summary>
        /// Number of packets transited on the network.
        /// </summary>
        public uint PacketsReceived
        {
            get => _packetsReceived;
        }

        /// <summary>
        /// Number of packets dropped by the driver.
        /// </summary>
        public uint PacketsDroppedByDriver
        {
            get => _packetsDroppedByDriver;
        }

        // TODO: Update documentation when support is added.
        /// <summary>
        /// Number of packets dropped by the interface.
        /// Not yet supported.
        /// </summary>
        public uint PacketsDroppedByInterface
        {
            get => _packetsDroppedByInterface;
        }

        /// <summary>
        /// Win32 specific. Number of packets captured, i.e number of packets that are accepted by the filter, that find place in the kernel buffer and therefore that actually reach the application.
        /// </summary>
        public uint PacketsCaptured
        {
            get => _packetsCaptured;
        }

        /// <inheritdoc/>
        public bool Equals(PacketTotalStatistics other)
        {
            if (other == null)
                return false;

            return (PacketsReceived == other.PacketsReceived &&
                    PacketsDroppedByDriver == other.PacketsDroppedByDriver &&
                    PacketsDroppedByInterface == other.PacketsDroppedByInterface &&
                    PacketsCaptured == other.PacketsCaptured);
        }

        /// <inheritdoc/>
        public override bool Equals(object obj)
        {
            return Equals(obj as PacketTotalStatistics);
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            return (int)
                (_packetsReceived ^
                _packetsDroppedByDriver ^
                _packetsDroppedByInterface ^
                _packetsCaptured);
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            return new StringBuilder()
            .Append("Packets Received: ")
            .Append(PacketsReceived)
            .Append(". ")
            .Append("Packets Dropped By Driver: ")
            .Append(PacketsDroppedByDriver)
            .Append(". ")
            .Append("Packets Dropped By Interface: ")
            .Append(PacketsDroppedByInterface)
            .Append(". ")
            .Append("Packets Captured: ")
            .Append(PacketsCaptured)
            .Append(".")
            .ToString();
        }
    }
}
