using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using PcapDotNet.Core.Native;
using PcapDotNet.Packets;
using static PcapDotNet.Core.Native.PcapUnmanagedStructures;

namespace PcapDotNet.Core
{
    /// <summary>
    /// Represents a buffer of packets to be sent.
    /// Note that transmitting a send buffer is much more efficient than performing a series of Send(), because the send buffer is buffered at kernel level drastically decreasing the number of context switches.
    /// </summary>
    public sealed class PacketSendBuffer : IDisposable
    {
        private byte[] _buffer;
        private int _currentBufferPosition;

        /// <summary>
        /// This function allocates a send buffer, i.e. a buffer containing a set of raw packets that will be transmitted on the network with PacketCommunicator.Transmit().
        /// </summary>
        /// <param name="capacity">The size, in bytes, of the buffer, therefore it determines the maximum amount of data that the buffer will contain.</param>
        public PacketSendBuffer(uint capacity)
        {
            _buffer = new byte[capacity];
        }

        /// <summary>
        /// Number of queued packets
        /// </summary>
        public int Length { get; private set; }

        /// <summary>
        /// Adds a raw packet at the end of the send buffer.
        /// 'Raw packet' means that the sending application will have to include the protocol headers, since every packet is sent to the network 'as is'. The CRC of the packets needs not to be calculated, because it will be transparently added by the network interface.
        /// </summary>
        /// <param name="packet">The packet to be added to the buffer</param>
        /// <exception cref="InvalidOperationException">Thrown on failure.</exception>
        public void Enqueue(Packet packet)
        {
            CheckDisposed();

            if (packet is null)
            {
                throw new ArgumentNullException(nameof(packet));
            }

            var hdrSize = Interop.Pcap.PcapHeaderSize;
            if (hdrSize + packet.Length > _buffer.Length - _currentBufferPosition)
            {
                throw new InvalidOperationException("Failed enqueueing to queue");
            }

            using (var headerHandle = new PcapPacketHeaderHandle(packet))
            {
                Marshal.Copy(headerHandle.Pointer, _buffer, _currentBufferPosition, hdrSize);
            }
            Buffer.BlockCopy(packet.Buffer, 0, _buffer, _currentBufferPosition + hdrSize, packet.Length);

            _currentBufferPosition += hdrSize + packet.Length;
            ++Length;
        }

        /// <summary>
        /// Deletes a send buffer and frees all the memory associated with it.
        /// </summary>
        public void Dispose()
        {
            _buffer = null;
        }

        internal unsafe void Transmit(PcapHandle /*pcap_t* */ pcapDescriptor, bool isSync)
        {
            CheckDisposed();

            if (_currentBufferPosition == 0)
            {
                // Npcap does not properly check for 0 packets queue
                // See https://github.com/nmap/npcap/issues/287
                return;
            }
            fixed (byte* buf = _buffer)
            {
                var pcapSendQueue = new pcap_send_queue
                {
                    maxlen = (uint)_buffer.Length,
                    len = (uint)_currentBufferPosition,
                    ptrBuff = new IntPtr(buf)
                };
                int numBytesTransmitted = Interop.Pcap.pcap_sendqueue_transmit(pcapDescriptor, ref pcapSendQueue, isSync ? 1 : 0);
                if(numBytesTransmitted < _currentBufferPosition)
                    PcapError.ThrowInvalidOperation("Failed transmitting packets from queue", pcapDescriptor);
            }
        }
#if NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void CheckDisposed()
        {
            if(_buffer == null)
            {
                throw new ObjectDisposedException(nameof(PacketSendBuffer));
            }
        }
    }
}
