using PcapDotNet.Core.Native;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace PcapDotNet.Core
{
    /// <summary>
    /// A live interface.
    /// </summary>
    public sealed class LivePacketDevice : PacketDevice
    {
        /// <summary>
        /// Create a list of local machine network devices that can be opened with Open().
        /// Platform independent.
        /// </summary>
        /// <returns>
        /// A readonly collection of LivePacketDevices.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        /// Thrown if some errors occurred. 
        /// An error could be due to several reasons:
        ///   <list type="bullet">
        ///     <item>libpcap/WinPcap was not installed on the local/remote host.</item>
        ///     <item>The user does not have enough privileges to list the devices.</item>
        ///     <item>A network problem.</item>
        ///     <item>other errors (not enough memory and others).</item>
        ///   </list>
        /// </exception>
        /// <remarks>
        /// There may be network devices that cannot be opened with Open() by the process calling AllLocalMachine, because, for example, that process might not have sufficient privileges to open them for capturing; if so, those devices will not appear on the list.
        /// </remarks>
        public static ReadOnlyCollection<LivePacketDevice> AllLocalMachine
        {
            get
            {
                const string NamePrefix = @"rpcap://\Device\NPF_";
                using (var devicePtrHandle = Interop.Pcap.GetAllLocalMachine())
                {
                    var nics = Interop.Pcap.GetAllNetworkInterfacesByDotNet();
                    var deviceList = new List<LivePacketDevice>();
                    foreach (var pcap_if in devicePtrHandle.GetManagedData())
                    {
                        deviceList.Add(new LivePacketDevice(pcap_if, nics.FirstOrDefault(networkInterface => Environment.OSVersion.Platform == PlatformID.Unix || Environment.OSVersion.Platform == PlatformID.MacOSX
                                                                                             ? pcap_if.Name == networkInterface.Id
                                                                                             : pcap_if.Name == NamePrefix + networkInterface.Id)));
                    }
                    return new ReadOnlyCollection<LivePacketDevice>(deviceList);
                }
            }
        }

        private LivePacketDevice(PcapUnmanagedStructures.pcap_if device, NetworkInterface networkInterface)
        {
            Name = device.Name;
            if (Environment.OSVersion.Platform != PlatformID.Unix && Environment.OSVersion.Platform != PlatformID.MacOSX)
                Description = device.Description;
            else
                Description = $"Network adapter '{device.Name}' on local host";
            Attributes = (DeviceAttributes)device.Flags;
            Attributes &= DeviceAttributes.Loopback;
            NetworkInterface = networkInterface;

            var addresses = new List<DeviceAddress>();
            var nextaddressPtr = device.Addresses;
            while (nextaddressPtr != IntPtr.Zero)
            {
                var pcap_addr = (PcapUnmanagedStructures.pcap_addr)Marshal.PtrToStructure(nextaddressPtr, typeof(PcapUnmanagedStructures.pcap_addr));
                if (pcap_addr.Addr != IntPtr.Zero)
                {
                    var sockaddr = (PcapUnmanagedStructures.sockaddr)Marshal.PtrToStructure(pcap_addr.Addr, typeof(PcapUnmanagedStructures.sockaddr));
                    var family = Interop.Sys.GetSocketAddressFamily(sockaddr.sa_family);
                    if (family == SocketAddressFamily.Internet || family == SocketAddressFamily.Internet6)
                    {
                        addresses.Add(new DeviceAddress(pcap_addr, family));
                    }
                }

                nextaddressPtr = pcap_addr.Next;
            }
            Addresses = new ReadOnlyCollection<DeviceAddress>(addresses);
        }

        /// <inheritdoc/>
        public override string Name { get; }

        /// <inheritdoc/>
        public override string Description { get; }

        /// <inheritdoc/>
        public override DeviceAttributes Attributes { get; }

        /// <summary>
        /// Returns if present the NetworkInterface.
        /// </summary>
        public NetworkInterface NetworkInterface { get; }

        /// <inheritdoc/>
        public override ReadOnlyCollection<DeviceAddress> Addresses { get; }

        /// <inheritdoc/>
        public override PacketCommunicator Open(int snapshotLength, PacketDeviceOpenAttributes attributes, int readTimeout)
        {
            var netmask = Addresses.Count > 0 ? Addresses[0].Netmask : null;
            return new LivePacketCommunicator(Name, snapshotLength, attributes, readTimeout, default, netmask);
        }
    }
}
