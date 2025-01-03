using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using PcapDotNet.Core.Extensions;
using Xunit;

namespace PcapDotNet.Core.Test
{
    /// <summary>
    /// Summary description for LivePacketDeviceExtensionsTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class LivePacketDeviceExtensionsTests
    {
#if !REAL
        public LivePacketDeviceExtensionsTests()
        {
            TestablePcapPal.UseTestPal();
        }
#endif

        [Fact]
        public void GetNetworkInterfaceNullTest()
        {
            Assert.Throws<ArgumentNullException>(() => LivePacketDeviceExtensions.GetNetworkInterface(null));
        }

        // this test tests on linux other paths!
        [Fact]
        public void GetMacAddressTest()
        {
            foreach (LivePacketDevice device in LivePacketDevice.AllLocalMachine)
            {
                if ((Environment.OSVersion.Platform == PlatformID.Unix || Environment.OSVersion.Platform == PlatformID.MacOSX)
                    && (device.Name == "any" || device.Name == "bluetooth-monitor" || device.Name == "nflog"
                        || device.Name == "nfqueue" || device.Name == "dbus-system" || device.Name == "dbus-session"))
                {
                    continue;
                }

                _ =  device.GetMacAddress();
            }
        }

        // this test tests on linux other paths!
        [Fact]
        public void GetMacAddress_Loopback_ReturnsZeroMac()
        {
            var loopback = LivePacketDevice.AllLocalMachine.First(n => (n.Attributes & DeviceAttributes.Loopback) != 0);

            Assert.Equal(Packets.Ethernet.MacAddress.Zero, loopback.GetMacAddress());
        }

        [Fact]
        public void GetGuidNullDeviceTest()
        {
            Assert.Throws<ArgumentNullException>(() => (null as LivePacketDevice).GetGuid());
        }
    }
}
