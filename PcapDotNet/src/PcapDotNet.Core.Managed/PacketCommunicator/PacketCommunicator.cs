﻿using System;
using System.Collections.ObjectModel;
using PcapDotNet.Packets;

namespace PcapDotNet.Core
{
    public delegate void HandlePacket(Packet packet);
    public delegate void HandleStatistics(PacketSampleStatistics statistics);

    public abstract class PacketCommunicator : IDisposable
    {
        private readonly IntPtr /* pcap_t* */ _pcapDescriptor;
        private readonly IpV4SocketAddress _ipV4Netmask;
        private PacketCommunicatorMode _mode;

        internal PacketCommunicator(IntPtr /* pcap_t* */ pcapDescriptor, SocketAddress netmask)
        {

        }

        /// <summary>
        /// Close the files associated with the capture and deallocates resources. 
        /// </summary>
        protected virtual void Dispose(bool disposing)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            Dispose(true);
        }
        
        ~PacketCommunicator()
        {
            Dispose(false);
        }

        /// <summary>
        /// pointer to a pcap_t struct
        /// </summary>
        protected IntPtr PcapDescriptor => _pcapDescriptor;

        /// <summary>
        /// The link layer of an adapter.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown when setting the datalink fails.</exception>
        public PcapDataLink DataLink
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        /// <summary>
        /// List of the supported data link types of the interface associated with the packet communicator.
        /// This property is currently unsupported to avoid memory leakage until a bug fix will be released in winpcap.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown on failure.</exception>
        public ReadOnlyCollection<PcapDataLink> SupportedDataLinks
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        /// <summary>
        /// The dimension of the packet portion (in bytes) that is delivered to the application. 
        /// </summary>
        public int SnapshotLength
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        /// <summary>
        /// The IPv4 netmask of the network on which packets are being captured; useful for filters when checking for IPv4 broadcast addresses in the filter program. If the netmask of the network on which packets are being captured isn't known to the program, or if packets are being captured on the Linux "any" pseudo-interface that can capture on more than one network, the value will be null and a filter that tests for IPv4 broadcast addreses won't be done correctly, but all other tests in the filter program will be OK.
        /// </summary>
        public IpV4SocketAddress IpV4Netmask
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        /// <summary>
        /// True if the current file uses a different byte order than the current system. 
        /// </summary>
        public bool IsFileSystemByteOrder
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        /// <summary>
        /// The major version number of the pcap library used to write the file.
        /// </summary>
        public int FileMajorVersion
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        /// <summary>
        /// The minor version number of the pcap library used to write the file.
        /// </summary>
        public int FileMinorVersion
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        /// <summary>
        /// Statistics on current capture.
        /// The values represent packet statistics from the start of the run to the time of the call. 
        /// Supported only on live captures, not on offline. No statistics are stored in offline, so no statistics are available when reading from an offline device.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown if there is an error or the underlying packet capture doesn't support packet statistics.</exception>
        public abstract PacketTotalStatistics TotalStatistics { get; }

        /// <summary>
        /// The working mode of the interface.
        /// </summary>
        public PacketCommunicatorMode Mode
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        /// <summary>
        /// Switch between blocking and nonblocking mode.
        /// Puts a live communicator into "non-blocking" mode, or takes it out of "non-blocking" mode.
        /// In "non-blocking" mode, an attempt to read from the communicator with ReceiveSomePackets will, if no packets are currently available to be read, return immediately rather than blocking waiting for packets to arrive.
        /// ReceivePacket and ReceivePackets will not work in "non-blocking" mode.
        /// <seealso cref="ReceiveSomePackets"/>
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown if there is an error.</exception>
        public bool NonBlocking
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        /// <summary>
        /// Set the size of the kernel buffer associated with an adapter.
        /// If an old buffer was already created with a previous call to SetKernelBufferSize(), it is deleted and its content is discarded.
        /// LivePacketDevice.Open() creates a 1 MByte buffer by default.
        /// <!--seealso cref="LivePacketDevice::Open"/-->
        /// </summary>
        /// <param name="size">the size of the buffer in bytes</param>
        /// <exception cref="InvalidOperationException">Thrown on failure.</exception>
        void SetKernelBufferSize(int size)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Set the minumum amount of data received by the kernel in a single call.
        /// Changes the minimum amount of data in the kernel buffer that causes a read from the application to return (unless the timeout expires).
        /// If the value of size is large, the kernel is forced to wait the arrival of several packets before copying the data to the user. 
        /// This guarantees a low number of system calls, i.e. low processor usage, and is a good setting for applications like packet-sniffers and protocol analyzers.
        /// Vice versa, in presence of a small value for this variable, the kernel will copy the packets as soon as the application is ready to receive them.
        /// This is useful for real time applications that need the best responsiveness from the kernel.
        /// </summary>
        /// <param name="size">minimum number of bytes to copy</param>
        /// <exception cref="InvalidOperationException">Thrown on failure.</exception>
        void SetKernelMinimumBytesToCopy(int size)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Define a sampling method for packet capture.
        /// This function allows applying a sampling method to the packet capture process. 
        /// The mtthod will be applied as soon as the capture starts.
        /// </summary>
        /// <remarks>
        /// Warning: Sampling parameters cannot be changed when a capture is active. These parameters must be applied before starting the capture. If they are applied when the capture is in progress, the new settings are ignored.
        /// Warning: Sampling works only when capturing data on Win32 or reading from a file. It has not been implemented on other platforms. Sampling works on remote machines provided that the probe (i.e. the capturing device) is a Win32 workstation. 
        /// </remarks>
        /// <param name="method">The sampling method to be applied</param>
        void SetSamplingMethod(SamplingMethod method)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Read a packet from an interface or from an offline capture.
        /// This function is used to retrieve the next available packet, bypassing the callback method traditionally provided.
        /// The method fills the packet parameter with the next captured packet.
        /// <seealso cref="ReceiveSomePackets"/>
        /// <seealso cref="ReceivePackets"/>
        /// </summary>
        /// <param name="packet">The received packet if it was read without problems. null otherwise.</param>
        /// <returns>
        ///   <list type="table">
        ///     <listheader>
        ///         <term>Return value</term>
        ///         <description>description</description>
        ///     </listheader>
        ///     <item><term>Ok</term><description>The packet has been read without problems.</description></item>
        ///     <item><term>Timeout</term><description>The timeout set with LivePacketDevice.Open() has elapsed. In this case the packet out parameter will be null.</description></item>
        ///     <item><term>Eof</term><description>EOF was reached reading from an offline capture. In this case the packet out parameter will be null.</description></item>
        ///   </list>
        /// </returns>
        /// <exception cref="InvalidOperationException">Thrown if the mode is not Capture or an error occurred.</exception>
        public PacketCommunicatorReceiveResult ReceivePacket(out Packet packet)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Collect a group of packets.
        /// Used to collect and process packets. 
        /// <seealso cref="ReceivePacket"/>
        /// <seealso cref="ReceivePackets"/>
        /// <seealso cref="Break"/>
        /// </summary>
        /// <param name="maxPackets">
        ///   <para>
        ///   Specifies the maximum number of packets to process before returning.
        ///   This is not a minimum number; when reading a live capture, only one bufferful of packets is read at a time, so fewer than maxPackets packets may be processed.
        ///   </para>
        ///   <para>A maxPackets of -1 processes all the packets received in one buffer when reading a live capture, or all the packets in the file when reading an offline capture.</para>
        /// </param>
        /// <param name="callback">Specifies a routine to be called with one argument: the packet received.</param>
        /// <param name="countGot">
        ///   <para>The number of packets read is returned.</para>
        ///   <para>0 is returned if no packets were read from a live capture (if, for example, they were discarded because they didn't pass the packet filter, or if, on platforms that support a read timeout that starts before any packets arrive, the timeout expires before any packets arrive, or if the communicator is in non-blocking mode and no packets were available to be read) or if no more packets are available in an offline capture.</para>
        /// </param>
        /// <returns>
        ///   <list type="table">
        ///     <listheader>
        ///         <term>Return value</term>
        ///         <description>description</description>
        ///     </listheader>
        ///     <item><term>Ok</term><description>countGot packets has been read without problems. This includes the case where a read timeout occurred and the case the communicator is in non-blocking mode and no packets were available</description></item>
        ///     <item><term>Eof</term><description>EOF was reached reading from an offline capture.</description></item>
        ///     <item><term>BreakLoop</term><description>Indicates that the loop terminated due to a call to Break() before any packets were processed.</description></item>
        ///   </list>
        /// </returns>
        /// <exception cref="InvalidOperationException">Thrown if the mode is not Capture or an error occurred.</exception>
        /// <remarks>
        ///   <para>Only the first bytes of data from the packet might be in the received packet (which won't necessarily be the entire packet; to capture the entire packet, you will have to provide a value for snapshortLength in your call to PacketDevice.Open() that is sufficiently large to get all of the packet's data - a value of 65536 should be sufficient on most if not all networks).</para>
        ///   <para>When reading a live capture, ReceiveSomePackets() will not necessarily return when the read times out; on some platforms, the read timeout isn't supported, and, on other platforms, the timer doesn't start until at least one packet arrives. This means that the read timeout should NOT be used in, for example, an interactive application, to allow the packet capture loop to ``poll'' for user input periodically, as there's no guarantee that ReceiveSomePackets() will return after the timeout expires.</para>
        /// </remarks>
        public PacketCommunicatorReceiveResult ReceiveSomePackets(out int countGot, int maxPackets, HandlePacket callback)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Collect a group of packets.
        /// Similar to ReceiveSomePackets() except it keeps reading packets until count packets are processed or an error occurs. It does not return when live read timeouts occur.
        /// <seealso cref="ReceivePacket"/>
        /// <seealso cref="ReceiveSomePackets"/>
        /// <seealso cref="Break"/>
        /// </summary>
        /// <param name="count">Number of packets to process. A negative count causes ReceivePackets() to loop forever (or at least until an error occurs).</param>
        /// <param name="callback">Specifies a routine to be called with one argument: the packet received.</param>
        /// <returns>
        ///   <list type="table">
        ///     <listheader>
        ///         <term>Return value</term>
        ///         <description>description</description>
        ///     </listheader>
        ///     <item><term>Ok</term><description>Count is exhausted</description></item>
        ///     <item><term>Eof</term><description>Count wasn't exhausted and EOF was reached reading from an offline capture.</description></item>
        ///     <item><term>BreakLoop</term><description>Indicates that the loop terminated due to a call to Break() before count packets were processed.</description></item>
        ///   </list>
        /// </returns>
        /// <exception cref="InvalidOperationException">Thrown if the mode is not Capture or an error occurred.</exception>
        public PacketCommunicatorReceiveResult ReceivePackets(int count, HandlePacket callback)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Receives a single statistics data on packets from an interface instead of receiving the packets.
        /// The statistics can be received in the resolution set by readTimeout when calling LivePacketDevice.Open().
        /// </summary>
        /// <param name="statistics">The received statistics if it was read without problems. null otherwise.</param>
        /// <returns>
        ///   <list type="table">
        ///     <listheader>
        ///         <term>Return value</term>
        ///         <description>description</description>
        ///     </listheader>
        ///     <item><term>Ok</term><description>The statistics has been read without problems. In statistics mode the readTimeout is always used and it never runs on offline captures so Ok is the only valid result.</description></item>
        ///   </list>
        /// </returns>
        /// <exception cref="InvalidOperationException">Thrown if the mode is not Statistics or an error occurred.</exception>
        public PacketCommunicatorReceiveResult ReceiveStatistics(out PacketSampleStatistics statistics)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Collect a group of statistics every readTimeout given in LivePacketDevice.Open().
        /// <seealso cref="Break"/>
        /// </summary>
        /// <param name="count">Number of statistics to process. A negative count causes ReceiveStatistics() to loop forever (or at least until an error occurs).</param>
        /// <param name="callback">Specifies a routine to be called with one argument: the statistics received.</param>
        /// <returns>
        ///   <list type="table">
        ///     <listheader>
        ///         <term>Return value</term>
        ///         <description>description</description>
        ///     </listheader>
        ///     <item><term>Ok</term><description>Count is exhausted</description></item>
        ///     <item><term>BreakLoop</term><descrition>Indicates that the loop terminated due to a call to Break() before count statistics were processed.</description></item>
        ///   </list>
        /// </returns>
        /// <exception cref="InvalidOperationException">Thrown if the mode is not Statistics or an error occurred.</exception>
        public PacketCommunicatorReceiveResult ReceiveStatistics(int count, HandleStatistics callback)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Set a flag that will force ReceiveSomePackets(), ReceivePackets() or ReceiveStatistics() to return rather than looping.
        /// They will return the number of packets/statistics that have been processed so far, with return value BreakLoop.
        /// <seealso cref="ReceiveSomePackets"/>
        /// <seealso cref="ReceivePackets"/>
        /// <seealso cref="ReceiveStatistics(int, HandleStatistics)"/>
        /// </summary>
        /// <remarks>
        ///   <list type="bullet">
        ///     <item>This routine is safe to use inside a signal handler on UNIX or a console control handler on Windows, as it merely sets a flag that is checked within the loop.</item>
        ///     <item>The flag is checked in loops reading packets from the OS - a signal by itself will not necessarily terminate those loops - as well as in loops processing a set of packets/statistics returned by the OS.</item>
        ///     <item>Note that if you are catching signals on UNIX systems that support restarting system calls after a signal, and calling Break() in the signal handler, you must specify, when catching those signals, that system calls should NOT be restarted by that signal. Otherwise, if the signal interrupted a call reading packets in a live capture, when your signal handler returns after calling Break(), the call will be restarted, and the loop will not terminate until more packets arrive and the call completes.</item>
        ///     <item>ReceivePacket() will, on some platforms, loop reading packets from the OS; that loop will not necessarily be terminated by a signal, so Break() should be used to terminate packet processing even if ReceivePacket() is being used.</item>
        ///     <item>Break() does not guarantee that no further packets/statistics will be processed by ReceiveSomePackets(), ReceivePackets() or ReceiveStatistics() after it is called; at most one more packet might be processed.</item>
        ///     <item>If BreakLoop is returned from ReceiveSomePackets(), ReceivePackets() or ReceiveStatistics(), the flag is cleared, so a subsequent call will resume reading packets. If a different return value is returned, the flag is not cleared, so a subsequent call will return BreakLoop and clear the flag.</item>
        ///   </list>
        /// </remarks>
        public void Break()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Send a raw packet.
        /// This function allows to send a raw packet to the network.
        /// <seealso cref="Transmit"/>
        /// </summary>
        /// <param name="packet">The packet to send (including the various protocol headers). The MAC CRC doesn't need to be included, because it is transparently calculated and added by the network interface driver.</param>
        /// <exception cref="InvalidOperationException">The packet wasn't successfully sent.</exception>
        public void SendPacket(Packet packet)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Send a buffer of packets to the network.
        /// This function transmits the content of a queue to the wire.
        /// <seealso cref="SendPacket"/>
        /// <seealso cref="PacketSendBuffer"/>
        /// </summary>
        /// <param name="sendBuffer">Contains the packets to send.</param>
        /// <param name="isSync">Determines if the send operation must be synchronized: if it is true, the packets are sent respecting the timestamps, otherwise they are sent as fast as possible.</param>
        /// <exception cref="InvalidOperationException">Trying to transmit to an offline device or an error occurred during the send. The error can be caused by a driver/adapter problem or by an inconsistent/bogus send buffer.</exception>
        /// <remarks>
        ///   <list type="bullet">
        ///     <item>Using this function is more efficient than issuing a series of SendPacket(), because the packets are buffered in the kernel driver, so the number of context switches is reduced. Therefore, expect a better throughput when using Transmit().</item>
        ///     <item>When isSync is true, the packets are synchronized in the kernel with a high precision timestamp. This requires a non-negligible amount of CPU, but allows normally to send the packets with a precision of some microseconds (depending on the accuracy of the performance counter of the machine). Such a precision cannot be reached sending the packets with SendPacket().</item>
        ///   </list>
        /// </remarks>
        public abstract void Transmit(PacketSendBuffer sendBuffer, bool isSync);

        /// <summary>
        /// Compile a packet filter according to the communicator IPv4 netmask.
        /// <seealso cref="SetFilter(BerkeleyPacketFilter^)"/>
        /// <!--seealso cref="SetFilter(String^)"/--> todo bug in documentation
        /// <seealso cref="BerkeleyPacketFilter"/>
        /// </summary>
        /// <param name="filterValue">A high level filtering expression (see <see href="http://www.winpcap.org/docs/docs_40_2/html/group__language.html">WinPcap Filtering expression syntax</see>)</param>
        /// <returns>
        /// The compiled filter that can be applied on the communicator.
        /// </returns>
        /// <exception cref="System::InvalidOperationException">An error occurred.</exception>
        /// <remarks>
        /// The created filter should be disposed by the user.
        /// </remarks>
        public BerkeleyPacketFilter CreateFilter(string filterValue)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Associate a filter to a capture.
        /// <seealso cref="CreateFilter"/>
        /// <seealso cref="BerkeleyPacketFilter"/>
        /// </summary>
        /// <param name="filter">The filter to associate. Usually the result of a call to CreateFilter().</param>
        /// <exception cref="InvalidOperationException">Thrown on failure.</exception>
        public void SetFilter(BerkeleyPacketFilter filter)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Compile and associate a filter to a capture.
        /// This method actually wraps a call to CreateFilter(), SetFilter() and Dispose().
        /// <seealso cref="CreateFilter"/>
        /// <seealso cref="BerkeleyPacketFilter"/>
        /// </summary>
        /// <param name="filterValue">A high level filtering expression (see <see href="http://www.winpcap.org/docs/docs_40_2/html/group__language.html">WinPcap Filtering expression syntax</see>).</param>
        /// <exception cref="InvalidOperationException">Thrown on failure.</exception>
        public void SetFilter(string filterValue)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Open a file to write packets.
        /// Called to open an offline capture for writing. The name "-" in a synonym for stdout. 
        /// </summary>
        /// <param name="fileName">Specifies the name of the file to open.</param>
        /// <returns>
        /// A dump file to dump packets capture by the communicator.
        /// </returns>
        /// <exception cref="InvalidOperationException">Thrown on failure.</exception>
        /// <remarks>
        /// The created dump file should be disposed by the user.
        /// Only ISO-8859-1 characters filenames are supported.
        /// </remarks>
        public PacketDumpFile OpenDump(string fileName)
        {
            throw new NotImplementedException();
        }

        protected InvalidOperationException BuildInvalidOperation(string errorMessage)
        {
            throw new NotImplementedException();
        }

        private static Packet CreatePacket(IntPtr /* const pcap_pkthdr& */ packetHeader, IntPtr /* const unsigned char* */ packetData, IDataLink dataLink)
        {
            throw new NotImplementedException();
        }

        //private PacketCommunicatorReceiveResult RunPcapNextEx(pcap_pkthdr** packetHeader, const unsigned char** packetData)

        //[System::Runtime::InteropServices::UnmanagedFunctionPointer(System::Runtime::InteropServices::CallingConvention::Cdecl)]
        //private delegate void HandlerDelegate(unsigned char* user, const struct pcap_pkthdr *packetHeader, const unsigned char* packetData);

        private void AssertMode(PacketCommunicatorMode mode)
        {
            throw new NotImplementedException();
        }

        private class PacketHandler
        {
            private readonly HandlePacket _callback;
            private readonly PcapDataLink _dataLink;
            int _packetCounter;

            public PacketHandler(HandlePacket callback, PcapDataLink dataLink)
            {
                _callback = callback;
                _dataLink = dataLink;
            }

            public int PacketCounter => _packetCounter;
            
            //public void Handle(unsigned char* user, const struct pcap_pkthdr *packetHeader, const unsigned char* packetData)        
        }

        private class StatisticsHandler
        {
            private readonly HandleStatistics _callback;
            
            public StatisticsHandler(HandleStatistics callback)
            {
                _callback = callback;
            }

            //public void Handle(unsigned char* user, const struct pcap_pkthdr *packetHeader, const unsigned char* packetData)
        }
        
    }
}
