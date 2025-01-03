using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using PcapDotNet.Base;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.TestUtils;
using Xunit;

namespace PcapDotNet.Core.Test
{
    /// <summary>
    /// Summary description for PacketDumpFileTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class PacketDumpFileTests
    {
#if !REAL
        public PacketDumpFileTests()
        {
            TestablePcapPal.UseTestPal();
        }
#endif

        [Fact]
        public void DumpWithoutDeviceTest()
        {
            string filename = Path.GetTempPath() + @"dump.pcap";

            Packet expectedPacket = PacketBuilder.Build(DateTime.Now,
                                                        new EthernetLayer
                                                        {
                                                            Source = new MacAddress(1),
                                                            Destination = new MacAddress(2),
                                                            EtherType = EthernetType.QInQ,
                                                        },
                                                        new PayloadLayer
                                                        {
                                                            Data = new Datagram(new byte[] {1, 2, 3})
                                                        });
            PacketDumpFile.Dump(filename, DataLinkKind.Ethernet, PacketDevice.DefaultSnapshotLength,
                                new[] {expectedPacket});
  
            using (PacketCommunicator communicator = new OfflinePacketDevice(filename).Open())
            {
                Packet actualPacket;
                PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out actualPacket);
                Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                Assert.Equal(expectedPacket, actualPacket);
                MoreAssert.IsInRange(expectedPacket.Timestamp.AddMicroseconds(-2), expectedPacket.Timestamp.AddMicroseconds(1), actualPacket.Timestamp);
            }
        }

        [Fact]
        public void SendNullPacketTest()
        {
            Assert.Throws<ArgumentNullException>(() => PacketDumpFile.Dump(@"dump.pcap", new PcapDataLink(DataLinkKind.Ethernet), PacketDevice.DefaultSnapshotLength, new Packet[1]));
        }

        [Fact]
        public void SendNullPacketsTest()
        {
            Assert.Throws<ArgumentNullException>(() => PacketDumpFile.Dump(@"dump.pcap", new PcapDataLink(DataLinkKind.Ethernet), PacketDevice.DefaultSnapshotLength, null));
        }
    }
}
