using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using PcapDotNet.Base;

namespace PcapDotNet.Core
{
    /// <summary>
    /// An offline interface - a pcap file to read packets from.
    /// </summary>
    public sealed class OfflinePacketDevice : PacketDevice
    {
        private readonly string _fileName;

        /// <summary>
        /// Creates a device object from a pcap file.
        /// The device can opened to read packets from.
        /// </summary>
        /// <param name="fileName">The name of the pcap file.</param>
        public OfflinePacketDevice(string fileName)
        {
            _fileName = fileName;
        }

        /// <summary>
        /// A string giving a name for the device.
        /// </summary>
        public override string Name
        {
            get { return _fileName; }
        }

        /// <summary>
        /// if not null, a string giving a human-readable description of the device.
        /// </summary>
        public override string Description
        {
            get { return string.Empty; }
        }

        /// <summary>
        /// Interface flags. Currently the only possible flag is Loopback, that is set if the interface is a loopback interface.
        /// </summary>
        public override DeviceAttributes Attributes
        {
            get { return DeviceAttributes.None; }
        }

        /// <summary>
        /// List of addresses for the interface.
        /// </summary>
        public override ReadOnlyCollection<DeviceAddress> Addresses
        {
            get { return new DeviceAddress[0].AsReadOnly(); }
        }

        /// <summary>
        /// Open a generic source in order to capture / send (WinPcap only) traffic.
        /// </summary>
        /// <param name="snapshotLength">length of the packet that has to be retained. For each packet received by the filter, only the first 'snapshotLength' bytes are stored in the buffer and passed to the user application. For instance, snaplen equal to 100 means that only the first 100 bytes of each packet are stored.</param>
        /// <param name="attributes">Keeps several flags that can be needed for capturing packets.</param>
        /// <param name="readTimeout">Read timeout in milliseconds. The read timeout is used to arrange that the read not necessarily return immediately when a packet is seen, but that it waits for some amount of time to allow more packets to arrive and to read multiple packets from the OS kernel in one operation. Not all platforms support a read timeout; on platforms that don't, the read timeout is ignored.</param>
        /// <exception cref="InvalidOperationException">Thrown on failure.</exception>
        public override PacketCommunicator Open(int snapshotLength, PacketDeviceOpenAttributes attributes, int readTimeout)
        {
            return new OfflinePacketCommunicator(_fileName);
        }
    }
}
