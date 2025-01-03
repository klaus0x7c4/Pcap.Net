using System;
using System.Diagnostics.CodeAnalysis;
using PcapDotNet.Packets;
using PcapDotNet.Packets.TestUtils;
using Xunit;

namespace PcapDotNet.Core.Test
{
    /// <summary>
    /// Summary description for BerkeleyPacketFilterTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class BerkeleyPacketFilterTests
    {
#if !REAL
        public BerkeleyPacketFilterTests()
        {
            TestablePcapPal.UseTestPal();
        }
#endif

        [Fact]
        public void BadFilterErrorTest()
        {
            using (PacketCommunicator communicator = LivePacketDeviceTests.OpenLiveDevice())
            {
                 Assert.Throws<ArgumentException>(() => communicator.SetFilter("illegal filter string"));
            }
        }

        // fails on REAL unix because no packets are sent
        [Fact]
        public void NoCommunicatorConstructorTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            Random random = new Random();
            Packet expectedPacket = random.NextEthernetPacket(1000, SourceMac, DestinationMac);
            Packet unexpectedPacket = random.NextEthernetPacket(1000, DestinationMac, SourceMac);

            using (BerkeleyPacketFilter filter = new BerkeleyPacketFilter("ether src " + SourceMac + " and ether dst " + DestinationMac, 1000, DataLinkKind.Ethernet))
            {
                using (PacketCommunicator communicator = LivePacketDeviceTests.OpenLiveDevice())
                {
                    TestFilter(communicator, filter, expectedPacket, unexpectedPacket);
                }
            }
        }

        // fails on REAL unix because no packets are sent
        [Fact]
        public void NoCommunicatorConstructorWithNetmaskTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            Random random = new Random();
            Packet expectedPacket = random.NextEthernetPacket(1000, SourceMac, DestinationMac);
            Packet unexpectedPacket = random.NextEthernetPacket(1000, DestinationMac, SourceMac);

            using (PacketCommunicator communicator = LivePacketDeviceTests.OpenLiveDevice())
            {
                using (BerkeleyPacketFilter filter = new BerkeleyPacketFilter("ether src " + SourceMac + " and ether dst " + DestinationMac, 1000, DataLinkKind.Ethernet, communicator.IpV4Netmask))
                {
                    TestFilter(communicator, filter, expectedPacket, unexpectedPacket);
                }
            }
        }

        [Fact]
        public void TestTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";
            const int SnapshotLength = 500;

            Random random = new Random();

            using (BerkeleyPacketFilter filter = new BerkeleyPacketFilter("ether src " + SourceMac + " and ether dst " + DestinationMac, SnapshotLength, DataLinkKind.Ethernet))
            {
                Assert.True(filter.Test(random.NextEthernetPacket(SnapshotLength / 2, SourceMac, DestinationMac)));
                Assert.True(filter.Test(random.NextEthernetPacket(SnapshotLength - 1, SourceMac, DestinationMac)));
                Assert.True(filter.Test(random.NextEthernetPacket(SnapshotLength, SourceMac, DestinationMac)));
                Assert.True(filter.Test(random.NextEthernetPacket(SnapshotLength + 1, SourceMac, DestinationMac)));
                Assert.True(filter.Test(random.NextEthernetPacket(SnapshotLength * 2, SourceMac, DestinationMac)));

                Assert.False(filter.Test(random.NextEthernetPacket(SnapshotLength / 2, DestinationMac, SourceMac)));

                int actualSnapshotLength;
                Assert.True(filter.Test(out actualSnapshotLength, random.NextEthernetPacket(SnapshotLength / 2, SourceMac, DestinationMac)));
                Assert.Equal(SnapshotLength, actualSnapshotLength);
            }
        }

        [Fact]
        public void TestNullTest()
        {
            using (BerkeleyPacketFilter filter = new BerkeleyPacketFilter("ether src 11:22:33:44:55:66", PacketDevice.DefaultSnapshotLength, DataLinkKind.Ethernet))
            {
                Assert.Throws<ArgumentNullException>(() => filter.Test(null));
            }
        }

        private static void TestFilter(PacketCommunicator communicator, BerkeleyPacketFilter filter, Packet expectedPacket, Packet unexpectedPacket)
        {
            communicator.SetFilter(filter);
            for (int i = 0; i != 5; ++i)
            {
                communicator.SendPacket(expectedPacket);
                communicator.SendPacket(unexpectedPacket);
            }

            Packet packet;
            PacketCommunicatorReceiveResult result;
            for (int i = 0; i != 5; ++i)
            {
                result = communicator.ReceivePacket(out packet);
                Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                Assert.Equal(expectedPacket, packet);
            }

            result = communicator.ReceivePacket(out packet);
            Assert.Equal(PacketCommunicatorReceiveResult.Timeout, result);
            Assert.Null(packet);
        }
    }
}
