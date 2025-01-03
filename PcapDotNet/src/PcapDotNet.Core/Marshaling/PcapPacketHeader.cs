using System;

namespace PcapDotNet.Core
{
    public sealed class PcapPacketHeader
    {
        public PcapPacketHeader(DateTime timestamp, uint packetLength, uint originalLength)
        {
            Timestamp = timestamp;
            PacketLength = packetLength;
            OriginalLength = originalLength;
        }

        public DateTime Timestamp { get; }

        /// <summary>
        /// The number of bytes this packet take
        /// </summary>
        public uint PacketLength { get; }

        /// <summary>
        /// Length this packet (off wire).
        /// When capturing, can be bigger than the number of captured bytes represented in Length.
        /// </summary>
        public uint OriginalLength { get; }
    }
}
