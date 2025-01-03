using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace PcapDotNet.Core.Extensions
{
    /// <summary>
    /// Extension methods for NetworkInterface class.
    /// </summary>
    public static class NetworkInterfaceExtensions
    {
        /// <summary>
        /// Returns the LivePacketDevice of the given NetworkInterface.
        /// The LivePacketDevice is found using the NetworkInterface's id and the LivePacketDevice's name.
        /// If no interface is found, null is returned.
        /// </summary>
        /// <param name="networkInterface">The NetworkInterface to look for a matching LivePacketDevice for.</param>
        /// <returns>The LivePacketDevice found according to the given NetworkInterface or null if none is found.</returns>
        public static LivePacketDevice GetLivePacketDevice(this NetworkInterface networkInterface)
        {
            if (networkInterface == null)
                throw new ArgumentNullException("networkInterface");

            return LivePacketDevice.AllLocalMachine.FirstOrDefault(device => Environment.OSVersion.Platform == PlatformID.Unix || Environment.OSVersion.Platform == PlatformID.MacOSX
                                                                       ? device.Name == networkInterface.Id
                                                                       : device.Name == LivePacketDeviceExtensions.NamePrefix + networkInterface.Id);
        }
    }
}
