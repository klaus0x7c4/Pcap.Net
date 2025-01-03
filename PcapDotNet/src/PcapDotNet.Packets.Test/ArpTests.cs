using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using PcapDotNet.Base;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.TestUtils;
using Xunit;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for ArpTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class ArpTests
    {
        [Fact]
        public void RandomArpTest()
        {
            Random random = new Random();

            for (int i = 0; i != 1000; ++i)
            {
                MacAddress ethernetSource = random.NextMacAddress();
                EthernetLayer ethernetLayer = new EthernetLayer
                {
                    Source = ethernetSource,
                };

                ArpLayer arpLayer = random.NextArpLayer();

                Packet packet = PacketBuilder.Build(DateTime.Now, ethernetLayer, arpLayer);

                Assert.True(packet.IsValid, "IsValid");

                // Ethernet
                Assert.Equal(packet.Length - EthernetDatagram.HeaderLengthValue, packet.Ethernet.PayloadLength);

                Assert.Equal(ethernetSource, packet.Ethernet.Source);
                Assert.Equal(EthernetDatagram.BroadcastAddress, packet.Ethernet.Destination);
                Assert.Equal(EthernetType.Arp, packet.Ethernet.EtherType);

                // Arp
                Assert.Equal(ArpDatagram.HeaderBaseLength + 2 * arpLayer.SenderHardwareAddress.Count + 2 * arpLayer.SenderProtocolAddress.Count, packet.Ethernet.Arp.Length);
                Assert.Equal(ArpHardwareType.Ethernet, packet.Ethernet.Arp.HardwareType);
                Assert.Equal(arpLayer, packet.Ethernet.Arp.ExtractLayer());
                Assert.NotEqual(arpLayer, random.NextArpLayer());
                Assert.Equal(arpLayer.GetHashCode(), packet.Ethernet.Arp.ExtractLayer().GetHashCode());
                ArpLayer differentArpLayer = random.NextArpLayer();
                Assert.NotEqual(arpLayer.GetHashCode(), differentArpLayer.GetHashCode());
            }
        }

        [Fact]
        public void ArpProtocolIpV4Address()
        {
            Packet packet = PacketBuilder.Build(DateTime.Now,
                                                new EthernetLayer
                                                {
                                                    Source = new MacAddress(),
                                                    EtherType = EthernetType.QInQ
                                                },
                                                new ArpLayer
                                                {
                                                    SenderHardwareAddress = new byte[8].AsReadOnly(),
                                                    SenderProtocolAddress = new byte[] { 1, 2, 3, 4 }.AsReadOnly(),
                                                    TargetHardwareAddress = new byte[8].AsReadOnly(),
                                                    TargetProtocolAddress = new byte[] { 11, 22, 33, 44 }.AsReadOnly(),
                                                    Operation = ArpOperation.Request,
                                                });

            Assert.Equal(new IpV4Address("1.2.3.4"), packet.Ethernet.Arp.SenderProtocolIpV4Address);
            Assert.Equal(new IpV4Address("11.22.33.44"), packet.Ethernet.Arp.TargetProtocolIpV4Address);
        }

        [Fact]
        public void ArpIncosistentSenderAddressSizeTest()
        {
            Assert.Throws<ArgumentException>(() =>
                PacketBuilder.Build(
                    DateTime.Now,
                    new EthernetLayer
                    {
                        Source = new MacAddress(),
                        EtherType = EthernetType.IpV4
                    },
                    new ArpLayer
                    {
                        SenderHardwareAddress = new byte[4].AsReadOnly(),
                        SenderProtocolAddress = new byte[6].AsReadOnly(),
                        TargetHardwareAddress = new byte[5].AsReadOnly(),
                        TargetProtocolAddress = new byte[6].AsReadOnly(),
                        Operation = ArpOperation.Request,
                    }));
        }

        [Fact]
        public void ArpIncosistentTargetAddressSizeTest()
        {
            Assert.Throws<ArgumentException>(() =>
                PacketBuilder.Build(
                    DateTime.Now,
                    new EthernetLayer
                    {
                        Source = new MacAddress(),
                        EtherType = EthernetType.IpV4
                    },
                    new ArpLayer
                    {
                        SenderHardwareAddress = new byte[4].AsReadOnly(),
                        SenderProtocolAddress = new byte[6].AsReadOnly(),
                        TargetHardwareAddress = new byte[4].AsReadOnly(),
                        TargetProtocolAddress = new byte[7].AsReadOnly(),
                        Operation = ArpOperation.Request,
                    }));
        }

        [Fact]
        public void ArpWriteNullPreviousLayerTest()
        {
            Assert.Throws<ArgumentNullException>(() => new ArpLayer().Write(new byte[0], 0, 0, null, new PayloadLayer()));
        }

        [Fact]
        public void ArpWriteBadPreviousLayerTest()
        {
            Assert.Throws<ArgumentException>(() => new ArpLayer().Write(new byte[0], 0, 0, new PayloadLayer(), new PayloadLayer()));
        }
    }
}
