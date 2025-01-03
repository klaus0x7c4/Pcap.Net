using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using PcapDotNet.Base;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.TestUtils;
using PcapDotNet.Packets.Transport;
using Xunit;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for EthernetTests.
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class EthernetTests
    {
        [Fact]
        public void RandomEthernetTest()
        {
            Random random = new Random();

            for (int i = 0; i != 1000; ++i)
            {
                EthernetLayer ethernetLayer = random.NextEthernetLayer();
                int ethernetPayloadLength = random.Next(1500);
                PayloadLayer payloadLayer = new PayloadLayer
                                                {
                                                    Data = random.NextDatagram(ethernetPayloadLength),
                                                };
                Packet packet = PacketBuilder.Build(DateTime.Now, ethernetLayer, payloadLayer);

                // Ethernet
                Assert.True(new[] {EthernetType.IpV4, EthernetType.IpV6, EthernetType.Arp, EthernetType.VLanTaggedFrame}.Contains(packet.Ethernet.EtherType) ||
                              packet.IsValid, "IsValid - EtherType = " + packet.Ethernet.EtherType);
                Assert.Equal(packet.Length - EthernetDatagram.HeaderLengthValue, packet.Ethernet.PayloadLength);
                Assert.Equal(ethernetLayer, packet.Ethernet.ExtractLayer());
                Assert.Equal(ethernetLayer.GetHashCode(), packet.Ethernet.ExtractLayer().GetHashCode());
                Assert.NotEqual(random.NextEthernetLayer().GetHashCode(), packet.Ethernet.ExtractLayer().GetHashCode());
                Assert.Equal(ethernetLayer.ToString(), packet.Ethernet.ExtractLayer().ToString());
                Assert.NotEqual(random.NextEthernetLayer().ToString(), packet.Ethernet.ExtractLayer().ToString());

                if (packet.Ethernet.EtherType == EthernetType.IpV4)
                    Assert.IsType<IpV4Datagram>(packet.Ethernet.Ip);
                else if (packet.Ethernet.EtherType == EthernetType.IpV6)
                    Assert.IsType<IpV6Datagram>(packet.Ethernet.Ip);
                else
                    Assert.Null(packet.Ethernet.Ip);

                Assert.Equal(payloadLayer.Data, packet.Ethernet.Payload);
            }
        }

        [Fact]
        public void AutomaticEthernetTypeNoNextLayer()
        {
            Assert.Throws<ArgumentException>(() => PacketBuilder.Build(DateTime.Now, new EthernetLayer()));
        }

        [Fact]
        public void AutomaticEthernetTypeBadNextLayer()
        {
            Assert.Throws<ArgumentException>(() => PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new TcpLayer()));
        }

        [Fact]
        public void NoPayloadByEtherType()
        {
            Packet packet = PacketBuilder.Build(DateTime.Now,
                                                new EthernetLayer
                                                    {
                                                        EtherType = EthernetType.AppleTalk
                                                    },
                                                new PayloadLayer
                                                    {
                                                        Data = new Datagram(new byte[100])
                                                    });
            Assert.True(packet.IsValid);
            Assert.Null(packet.Ethernet.Padding);
            Assert.Null(packet.Ethernet.Trailer);
            Assert.Null(packet.Ethernet.FrameCheckSequence);
            Assert.Null(packet.Ethernet.ExtraData);
        }

        [Fact]
        public void EmptyPadding()
        {
            Packet packet = PacketBuilder.Build(DateTime.Now,
                                                new EthernetLayer
                                                {
                                                    EtherType = EthernetType.AppleTalk
                                                },
                                                new PayloadLayer
                                                {
                                                    Data = new Datagram(new byte[10])
                                                });
            Assert.True(packet.IsValid);
            Assert.Equal(DataSegment.Empty, packet.Ethernet.Padding);
        }

        [Fact]
        public void PayloadTooBigForPadding()
        {
            Packet packet = PacketBuilder.Build(DateTime.Now,
                                                new EthernetLayer(),
                                                new ArpLayer
                                                {
                                                    ProtocolType = EthernetType.IpV4,
                                                    Operation = ArpOperation.DynamicReverseError,
                                                    SenderHardwareAddress = new byte[12].AsReadOnly(),
                                                    SenderProtocolAddress = new byte[22].AsReadOnly(),
                                                    TargetHardwareAddress = new byte[12].AsReadOnly(),
                                                    TargetProtocolAddress = new byte[22].AsReadOnly(),
                                                });
            Assert.True(packet.IsValid);
            Assert.Equal(DataSegment.Empty, packet.Ethernet.Padding);
        }
    }
}
