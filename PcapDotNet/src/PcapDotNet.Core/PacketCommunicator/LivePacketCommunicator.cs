using PcapDotNet.Core.Native;
using System;

namespace PcapDotNet.Core
{
    /// <summary>
    /// A network device packet communicator.
    /// </summary>
    public sealed class LivePacketCommunicator : PacketCommunicator
    {
        internal LivePacketCommunicator(
            string source,
            int snapshotLength,
            PacketDeviceOpenAttributes attributes,
            int readTimeout,
            PcapUnmanagedStructures.pcap_rmtauth auth,
            SocketAddress netmask)
            : base(netmask)
        {
            try
            {
                PcapDescriptor = PcapOpen(source, snapshotLength, attributes, readTimeout, auth);
            }
            catch (Exception)
            {
                GC.SuppressFinalize(this);
                throw;
            }
        }

        /// <summary>
        /// Statistics on current capture.
        /// The values represent packet statistics from the start of the run to the time of the call. 
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown if there is an error or the underlying packet capture doesn't support packet statistics.</exception>
        public override PacketTotalStatistics TotalStatistics
        {
            get { return Interop.Pcap.GetTotalStatistics(PcapDescriptor); }
        }

        /// <summary>
        /// Send a buffer of packets to the network.
        /// This function transmits the content of a queue to the wire.
        /// <seealso cref="PacketCommunicator.SendPacket"/>
        /// <seealso cref="PacketSendBuffer"/>
        /// </summary>
        /// <param name="sendBuffer">Contains the packets to send.</param>
        /// <param name="isSync">Determines if the send operation must be synchronized: if it is true, the packets are sent respecting the timestamps, otherwise they are sent as fast as possible.</param>
        /// <exception cref="InvalidOperationException">An error occurred during the send. The error can be caused by a driver/adapter problem or by an inconsistent/bogus send buffer..</exception>
        /// <remarks>
        ///   <list type="bullet">
        ///     <item>Using this function is more efficient than issuing a series of SendPacket(), because the packets are buffered in the kernel driver, so the number of context switches is reduced. Therefore, expect a better throughput when using Transmit().</item>
        ///     <item>When isSync is true, the packets are synchronized in the kernel with a high precision timestamp. This requires a non-negligible amount of CPU, but allows normally to send the packets with a precision of some microseconds (depending on the accuracy of the performance counter of the machine). Such a precision cannot be reached sending the packets with SendPacket().</item>
        ///     <item>On Windows with intel network adapter you will receive packets twice since npcap 0.999.</item>
        ///   </list>
        /// </remarks>
        public override void Transmit(PacketSendBuffer sendBuffer, bool isSync)
        {
            if (sendBuffer is null)
            {
                throw new ArgumentNullException(nameof(sendBuffer));
            }

            sendBuffer.Transmit(PcapDescriptor, isSync);
        }

        private static PcapHandle PcapOpen(string source, int snapshotLength, PacketDeviceOpenAttributes attributes, int readTimeout, PcapUnmanagedStructures.pcap_rmtauth auth)
        {
            var handle = Interop.Pcap.pcap_open(
                source,                 // name of the device
                snapshotLength,         // portion of the packet to capture
                                        // 65536 guarantees that the whole packet will be captured on all the link layers
                (int)attributes,
                readTimeout,
                ref auth,               // authentication on the remote machine
                out var errorBuffer);

            if (handle.IsInvalid)
            {
                PcapError.ThrowInvalidOperation($"Unable to open the adapter. Adapter name: {source}. Error: {errorBuffer}", null);
            }

            return handle;
        }
    };
}
