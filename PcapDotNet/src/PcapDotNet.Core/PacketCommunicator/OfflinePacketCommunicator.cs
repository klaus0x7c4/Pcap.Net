using System;
using PcapDotNet.Core.Native;

namespace PcapDotNet.Core
{
    /// <summary>
    /// Used to read packets from a (pcap) file on disk.
    /// </summary>
    public sealed class OfflinePacketCommunicator : PacketCommunicator
    {
        internal OfflinePacketCommunicator(string fileName)
            : base(OpenFile(fileName), null)
        { }

        /// <summary>
        /// TotalStatistics is not supported on offline captures.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown always.</exception>
        public override PacketTotalStatistics TotalStatistics
        {
            get { throw new InvalidOperationException("Can't get " + nameof(PacketTotalStatistics) + " for offline devices"); }
        }

        /// <summary>
        /// Transmit is not supported on offline captures.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown always.</exception>
        public override void Transmit(PacketSendBuffer sendBuffer, bool isSync)
        {
            throw new InvalidOperationException("Can't transmit queue to an offline device");
        }

        private static PcapHandle OpenFile(string fileName)
        {
            if (fileName is null)
            {
                throw new ArgumentNullException(nameof(fileName));
            }

            // ToDo: This is currently still very simplified
            // compared to the original native version. Still needs to be revised.

            var handle = Interop.Pcap.pcap_open_offline(fileName, out var errorBuffer);
            if (handle.IsInvalid)
            {
                throw new InvalidOperationException($"Failed opening file {fileName}. Error: {errorBuffer}.");
            }

            return handle;
        }
    };
}
