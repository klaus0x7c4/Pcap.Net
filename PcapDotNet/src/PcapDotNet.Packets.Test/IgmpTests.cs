using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Igmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.TestUtils;
using PcapDotNet.TestUtils;
using Xunit;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for IgmpTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class IgmpTests
    {
        [Fact]
        public void RandomIgmpTest()
        {
            EthernetLayer ethernetLayer = new EthernetLayer
            {
                Source = new MacAddress("00:01:02:03:04:05"),
                Destination = new MacAddress("A0:A1:A2:A3:A4:A5")
            };

            int seed = new Random().Next();
            Console.WriteLine("Seed: " + seed);
            Random random = new Random(seed);

            for (int i = 0; i != 200; ++i)
            {
                IpV4Layer ipV4Layer = random.NextIpV4Layer(null);
                ipV4Layer.HeaderChecksum = null;
                Layer ipLayer = random.NextBool() ? (Layer)ipV4Layer : random.NextIpV6Layer(IpV4Protocol.InternetGroupManagementProtocol, false);

                IgmpLayer igmpLayer = random.NextIgmpLayer();

                Packet packet = PacketBuilder.Build(DateTime.Now, ethernetLayer, ipLayer, igmpLayer);

                Assert.True(packet.IsValid, "IsValid");

                // Ethernet
                ethernetLayer.EtherType = ipLayer == ipV4Layer ? EthernetType.IpV4 : EthernetType.IpV6;
                Assert.Equal(ethernetLayer, packet.Ethernet.ExtractLayer());
                ethernetLayer.EtherType = EthernetType.None;

                // IP.
                if (ipV4Layer == ipLayer)
                {
                    // IPv4.
                    ipV4Layer.Protocol = IpV4Protocol.InternetGroupManagementProtocol;
                    ipV4Layer.HeaderChecksum = ((IpV4Layer)packet.Ethernet.IpV4.ExtractLayer()).HeaderChecksum;
                    Assert.Equal(ipV4Layer, packet.Ethernet.IpV4.ExtractLayer());
                    ipV4Layer.HeaderChecksum = null;
                }
                else
                {
                    // IPv6.
                    Assert.Equal(ipLayer, packet.Ethernet.IpV6.ExtractLayer());
                }

                // IGMP
                Assert.True(packet.Ethernet.Ip.Igmp.IsChecksumCorrect);
                Assert.Equal(igmpLayer, packet.Ethernet.Ip.Igmp.ExtractLayer());
                Assert.Equal(igmpLayer.GetHashCode(), packet.Ethernet.Ip.Igmp.ExtractLayer().GetHashCode());
                Assert.NotEqual<Layer>(igmpLayer, random.NextPayloadLayer(igmpLayer.Length));
                Assert.NotEqual(igmpLayer.GetHashCode(), random.NextPayloadLayer(igmpLayer.Length).GetHashCode());
                if (packet.Ethernet.Ip.Igmp.QueryVersion != IgmpQueryVersion.Version3)
                    MoreAssert.IsSmallerOrEqual(IgmpDatagram.MaxMaxResponseTime, packet.Ethernet.Ip.Igmp.MaxResponseTime);
                if (packet.Ethernet.Ip.Igmp.MessageType != IgmpMessageType.MembershipQuery)
                    Assert.Equal(IgmpQueryVersion.None, packet.Ethernet.Ip.Igmp.QueryVersion);
                switch (igmpLayer.MessageTypeValue)
                {
                    case IgmpMessageType.CreateGroupRequestVersion0:
                    case IgmpMessageType.CreateGroupReplyVersion0:
                    case IgmpMessageType.JoinGroupRequestVersion0:
                    case IgmpMessageType.JoinGroupReplyVersion0:
                    case IgmpMessageType.LeaveGroupRequestVersion0:
                    case IgmpMessageType.LeaveGroupReplyVersion0:
                    case IgmpMessageType.ConfirmGroupRequestVersion0:
                    case IgmpMessageType.ConfirmGroupReplyVersion0:
                        Assert.Equal(0, packet.Ethernet.Ip.Igmp.Version);
                        IgmpVersion0Layer igmpVersion0Layer = (IgmpVersion0Layer)igmpLayer;
                        Assert.Equal(igmpVersion0Layer.IdentifierValue, packet.Ethernet.Ip.Igmp.Identifier);
                        Assert.Equal(igmpVersion0Layer.AccessKeyValue, packet.Ethernet.Ip.Igmp.AccessKey);

                        switch (igmpLayer.MessageTypeValue)
                        {
                            case IgmpMessageType.CreateGroupRequestVersion0:
                                Assert.Equal(((IgmpCreateGroupRequestVersion0Layer)igmpLayer).CreateGroupRequestCode, packet.Ethernet.Ip.Igmp.CreateGroupRequestCode);
                                break;

                            case IgmpMessageType.CreateGroupReplyVersion0:
                            case IgmpMessageType.JoinGroupReplyVersion0:
                            case IgmpMessageType.LeaveGroupReplyVersion0:
                            case IgmpMessageType.ConfirmGroupReplyVersion0:
                                IgmpReplyVersion0Layer igmpReplyVersion0Layer = (IgmpReplyVersion0Layer)igmpVersion0Layer;
                                Assert.Equal(igmpReplyVersion0Layer.Code, packet.Ethernet.Ip.Igmp.ReplyCode);
                                if (packet.Ethernet.Ip.Igmp.ReplyCode == IgmpVersion0ReplyCode.RequestPendingRetryInThisManySeconds)
                                    Assert.Equal(igmpReplyVersion0Layer.RetryInThisManySeconds, packet.Ethernet.Ip.Igmp.RetryInThisManySeconds);
                                break;
                        }

                        break;

                    case IgmpMessageType.MembershipQuery:
                        switch (igmpLayer.QueryVersion)
                        {
                            case IgmpQueryVersion.Version1:
                                Assert.Equal(1, packet.Ethernet.Ip.Igmp.Version);
                                break;

                            case IgmpQueryVersion.Version2:
                                Assert.Equal(2, packet.Ethernet.Ip.Igmp.Version);
                                break;

                            case IgmpQueryVersion.Version3:
                                Assert.Equal(3, packet.Ethernet.Ip.Igmp.Version);
                                break;

                            default:
                                Assert.False(true, igmpLayer.QueryVersion.ToString());
                                break;
                        }
                        break;

                    case IgmpMessageType.MembershipReportVersion1:
                        Assert.Equal(1, packet.Ethernet.Ip.Igmp.Version);
                        break;

                    case IgmpMessageType.MembershipReportVersion2:
                    case IgmpMessageType.LeaveGroupVersion2:
                        Assert.Equal(2, packet.Ethernet.Ip.Igmp.Version);
                        break;

                    case IgmpMessageType.MembershipReportVersion3:
                        Assert.Equal(3, packet.Ethernet.Ip.Igmp.Version);
                        break;

                    default:
                        Assert.False(true, igmpLayer.MessageTypeValue.ToString());
                        break;
                }
                foreach (IgmpGroupRecordDatagram groupRecord in packet.Ethernet.Ip.Igmp.GroupRecords)
                    Assert.NotNull(groupRecord.ToString());
            }
        }

        [Fact]
        public void IgmpQueryVersion3SmallMaxResponseTimeTest()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(),
                                                 new IgmpQueryVersion3Layer
                                                 {
                                                     MaxResponseTime = TimeSpan.FromSeconds(-1),
                                                     QueryInterval = TimeSpan.FromSeconds(1)
                                                 }));
        }

        [Fact]
        public void IgmpQueryVersion3BigMaxResponseTimeTest()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(),
                                                 new IgmpQueryVersion3Layer
                                                 {
                                                     MaxResponseTime = TimeSpan.FromHours(1),
                                                     QueryInterval = TimeSpan.FromSeconds(1)
                                                 }));
        }

        [Fact]
        public void IgmpQueryVersion3SmallQueryIntervalTest()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(),
                                                 new IgmpQueryVersion3Layer
                                                 {
                                                     MaxResponseTime = TimeSpan.FromSeconds(1),
                                                     QueryInterval = TimeSpan.FromSeconds(-1)
                                                 }));
        }

        [Fact]
        public void IgmpQueryVersion3BigQueryIntervalTest()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(),
                                     new IgmpQueryVersion3Layer
                                     {
                                         MaxResponseTime = TimeSpan.FromSeconds(1),
                                         QueryInterval = TimeSpan.FromHours(9)
                                     }));
        }

        [Fact]
        public void IgmpQueryVersion2SmallMaxResponseTimeTest()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => PacketBuilder.Build(DateTime.Now,
                                                 new EthernetLayer(), new IpV4Layer(),
                                                 new IgmpQueryVersion2Layer
                                                 {
                                                     MaxResponseTime = TimeSpan.FromSeconds(-1)
                                                 }));
        }

        [Fact]
        public void IgmpQueryVersion2BigMaxResponseTimeTest()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(),
                                                 new IgmpQueryVersion2Layer
                                                 {
                                                     MaxResponseTime = TimeSpan.FromMinutes(5)
                                                 }));
        }

        [Fact]
        public void IgmpInvalidTest()
        {
            Packet queryVersion2 = PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(),
                                                        new IgmpQueryVersion2Layer
                                                        {
                                                            MaxResponseTime = TimeSpan.FromSeconds(1),
                                                        });

            Assert.True(queryVersion2.IsValid);
            Assert.True(queryVersion2.Ethernet.IpV4.Igmp.IsChecksumCorrect);

            // Small Packet
            byte[] buffer = new byte[queryVersion2.Length - 1];
            queryVersion2.Buffer.BlockCopy(0, buffer, 0, buffer.Length);
            Packet smallQueryVersion2 = new Packet(buffer, queryVersion2.Timestamp, queryVersion2.DataLink);
            Assert.False(smallQueryVersion2.IsValid);

            // Bad checksum
            buffer = new byte[queryVersion2.Length];
            queryVersion2.Buffer.BlockCopy(0, buffer, 0, buffer.Length);
            ++buffer[buffer.Length - 1];
            Packet badChecksumPacket = new Packet(buffer, queryVersion2.Timestamp, queryVersion2.DataLink);
            Assert.False(badChecksumPacket.Ethernet.IpV4.Igmp.IsChecksumCorrect);
            Assert.False(badChecksumPacket.IsValid);

            // Big query version 3
            Packet queryVersion3 = PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(),
                                                        new IgmpQueryVersion3Layer
                                                        {
                                                            MaxResponseTime = TimeSpan.FromSeconds(1),
                                                            QueryInterval = TimeSpan.FromSeconds(1),
                                                        });
            Assert.True(queryVersion3.IsValid, "IsValid");
            buffer = new byte[queryVersion3.Length + 2];
            queryVersion3.Buffer.BlockCopy(0, buffer, 0, queryVersion3.Length);
            buffer[EthernetDatagram.HeaderLengthValue + 3] += 2;
            buffer[EthernetDatagram.HeaderLengthValue + 11] -= 2;
            Packet bigQueryVersion3 = new Packet(buffer, queryVersion3.Timestamp, queryVersion3.DataLink);
            Assert.True(bigQueryVersion3.Ethernet.IpV4.Igmp.IsChecksumCorrect);
            Assert.True(bigQueryVersion3.Ethernet.IpV4.IsHeaderChecksumCorrect, "IpV4.IsHeaderChecksumCorrect");
            Assert.False(bigQueryVersion3.IsValid, "bigQueryVersion3.IsValid");

            // Big report version 1
            Packet reportVersion1 = PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(), new IgmpReportVersion1Layer());

            buffer = new byte[reportVersion1.Length + 2];
            reportVersion1.Buffer.BlockCopy(0, buffer, 0, reportVersion1.Length);
            buffer[EthernetDatagram.HeaderLengthValue + 3] += 2;
            buffer[EthernetDatagram.HeaderLengthValue + 11] -= 2;
            Packet bigReportVersion1 = new Packet(buffer, reportVersion1.Timestamp, reportVersion1.DataLink);
            Assert.True(bigReportVersion1.Ethernet.IpV4.Igmp.IsChecksumCorrect);
            Assert.True(bigReportVersion1.Ethernet.IpV4.IsHeaderChecksumCorrect);
            Assert.False(bigReportVersion1.IsValid);

            // Non zero max response code for report version 1
            buffer = new byte[reportVersion1.Length];
            reportVersion1.Buffer.BlockCopy(0, buffer, 0, buffer.Length);
            buffer.Write(EthernetDatagram.HeaderLengthValue + IpV4Datagram.HeaderMinimumLength + 1, 1);
            buffer.Write(EthernetDatagram.HeaderLengthValue + IpV4Datagram.HeaderMinimumLength + 2, (ushort)0xedfe, Endianity.Big);
            Packet nonZeroMaxResponseCodeReportVersion1 = new Packet(buffer, reportVersion1.Timestamp, reportVersion1.DataLink);
            Assert.True(nonZeroMaxResponseCodeReportVersion1.Ethernet.IpV4.Igmp.IsChecksumCorrect);
            Assert.True(nonZeroMaxResponseCodeReportVersion1.Ethernet.IpV4.IsHeaderChecksumCorrect);
            Assert.False(nonZeroMaxResponseCodeReportVersion1.IsValid);

            // Big report version 2
            Packet reportVersion2 = PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(),
                                                         new IgmpReportVersion2Layer
                                                         {
                                                             MaxResponseTime = TimeSpan.FromSeconds(1)
                                                         });

            buffer = new byte[reportVersion2.Length + 2];
            reportVersion2.Buffer.BlockCopy(0, buffer, 0, reportVersion2.Length);
            buffer[EthernetDatagram.HeaderLengthValue + 3] += 2;
            buffer[EthernetDatagram.HeaderLengthValue + 11] -= 2;
            Packet bigReportVersion2 = new Packet(buffer, reportVersion2.Timestamp, reportVersion2.DataLink);
            Assert.True(bigReportVersion2.Ethernet.IpV4.Igmp.IsChecksumCorrect);
            Assert.True(bigReportVersion2.Ethernet.IpV4.IsHeaderChecksumCorrect);
            Assert.False(bigReportVersion2.IsValid);

            // non zero max response code report version 3
            Packet reportVersion3 = PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(),
                                                        new IgmpReportVersion3Layer
                                                        {
                                                            GroupRecords = new ReadOnlyCollection<IgmpGroupRecord>(new[]
                                                                           {
                                                                               new IgmpGroupRecord(
                                                                                   IgmpRecordType.CurrentStateRecordModeIsExclude,
                                                                                   IpV4Address.Zero, new List<IpV4Address>(), Datagram.Empty)
                                                                           })
                                                        });

            buffer = new byte[reportVersion3.Length];
            reportVersion3.Buffer.BlockCopy(0, buffer, 0, buffer.Length);
            buffer.Write(EthernetDatagram.HeaderLengthValue + IpV4Datagram.HeaderMinimumLength + 1, 1);
            buffer.Write(EthernetDatagram.HeaderLengthValue + IpV4Datagram.HeaderMinimumLength + 2, (ushort)0xdbfd, Endianity.Big);
            Packet nonZeroMaxResponseCodeReportVersion3 = new Packet(buffer, reportVersion3.Timestamp, reportVersion3.DataLink);
            Assert.True(nonZeroMaxResponseCodeReportVersion3.Ethernet.IpV4.Igmp.IsChecksumCorrect);
            Assert.True(nonZeroMaxResponseCodeReportVersion3.Ethernet.IpV4.IsHeaderChecksumCorrect);
            Assert.False(nonZeroMaxResponseCodeReportVersion3.IsValid);

            // big report version 3
            buffer = new byte[reportVersion3.Length + 2];
            reportVersion3.Buffer.BlockCopy(0, buffer, 0, reportVersion3.Length);
            buffer[EthernetDatagram.HeaderLengthValue + 3] += 2;
            buffer[EthernetDatagram.HeaderLengthValue + 11] -= 2;
            Packet bigReportVersion3 = new Packet(buffer, reportVersion3.Timestamp, reportVersion3.DataLink);
            Assert.True(bigReportVersion3.Ethernet.IpV4.Igmp.IsChecksumCorrect);
            Assert.True(bigReportVersion3.Ethernet.IpV4.IsHeaderChecksumCorrect);
            Assert.False(bigReportVersion3.IsValid);

            // invalid group record report version 3
            buffer = new byte[reportVersion3.Length];
            reportVersion3.Buffer.BlockCopy(0, buffer, 0, reportVersion3.Length);
            buffer.Write(EthernetDatagram.HeaderLengthValue + IpV4Datagram.HeaderMinimumLength + IgmpDatagram.HeaderLength + 1, 1);
            buffer.Write(EthernetDatagram.HeaderLengthValue + IpV4Datagram.HeaderMinimumLength + 2, (ushort)0xdbfd, Endianity.Big);
            Packet invalidGroupRecordReportVersion3 = new Packet(buffer, reportVersion3.Timestamp, reportVersion3.DataLink);
            Assert.True(invalidGroupRecordReportVersion3.Ethernet.IpV4.Igmp.IsChecksumCorrect);
            Assert.True(invalidGroupRecordReportVersion3.Ethernet.IpV4.IsHeaderChecksumCorrect);
            Assert.False(invalidGroupRecordReportVersion3.IsValid);
        }

        [Fact]
        public void IgmpIllegalReportVersionTest()
        {
            Packet packet = PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(), new IgmpReportVersion1Layer());

            Assert.True(packet.IsValid);
            Assert.Equal(1, packet.Ethernet.IpV4.Igmp.Version);

            byte[] buffer = new byte[packet.Length];
            packet.Buffer.BlockCopy(0, buffer, 0, buffer.Length);
            buffer.Write(EthernetDatagram.HeaderLengthValue + IpV4Datagram.HeaderMinimumLength, 0);
            Packet illegalPacket = new Packet(buffer, packet.Timestamp, packet.DataLink);
            Assert.False(illegalPacket.IsValid);
            Assert.Equal(-1, illegalPacket.Ethernet.IpV4.Igmp.Version);
        }

        [Fact]
        public void IgmpIllegalQueryVersionTest()
        {
            Packet packet = PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(), new IgmpQueryVersion1Layer());

            Assert.True(packet.IsValid);
            Assert.Equal(1, packet.Ethernet.IpV4.Igmp.Version);

            byte[] buffer = new byte[packet.Length - 1];
            packet.Buffer.BlockCopy(0, buffer, 0, buffer.Length);
            Packet illegalPacket = new Packet(buffer, packet.Timestamp, packet.DataLink);
            Assert.False(illegalPacket.IsValid);
            Assert.Throws<InvalidOperationException>(() => illegalPacket.Ethernet.IpV4.Igmp.Version);
        }

        [Fact]
        public void IgmpGroupRecordBadAuxiliaryDataLengthTest()
        {
            Assert.Throws<ArgumentException>(() => new IgmpGroupRecord(IgmpRecordType.SourceListChangeAllowNewSources, IpV4Address.Zero, new List<IpV4Address>(),
                                                         new Datagram(new byte[] { 1 })));
        }

        [Fact]
        public void IgmpGroupRecordTest()
        {
            IgmpGroupRecord record = new IgmpGroupRecord(IgmpRecordType.SourceListChangeAllowNewSources, IpV4Address.Zero, new List<IpV4Address>(),
                                                         Datagram.Empty);
            Assert.True(record.Equals((object)record));
            Assert.Equal(record.GetHashCode(), record.GetHashCode());
            Assert.Equal(record.ToString(), record.ToString());
            Assert.False(record.Equals(null));
            Assert.NotEqual(record, new IgmpGroupRecord(IgmpRecordType.CurrentStateRecordModeIsExclude, record.MulticastAddress, record.SourceAddresses, record.AuxiliaryData));
            Assert.NotEqual(record, new IgmpGroupRecord(record.RecordType, new IpV4Address("1.2.3.4"), record.SourceAddresses, record.AuxiliaryData));
            Assert.NotEqual(record, new IgmpGroupRecord(record.RecordType, record.MulticastAddress, new List<IpV4Address>(new[] { new IpV4Address("2.3.4.5") }), record.AuxiliaryData));
            Assert.NotEqual(record, new IgmpGroupRecord(record.RecordType, record.MulticastAddress, record.SourceAddresses, new Datagram(new byte[12])));
            Assert.NotEqual(record.ToString(), new IgmpGroupRecord(record.RecordType, record.MulticastAddress, record.SourceAddresses, new Datagram(new byte[12])).ToString());
        }

        [Fact]
        public void IgmpExtractLayerBadMessageTypeTest()
        {
            Packet packet = PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(), new IgmpReportVersion1Layer());
            Assert.NotNull(packet.Ethernet.IpV4.Igmp.ExtractLayer());
            byte[] buffer = (byte[])packet.Buffer.Clone();
            buffer[packet.Length - packet.Ethernet.IpV4.Igmp.Length] = 0xFF;
            packet = new Packet(buffer, DateTime.Now, packet.DataLink);
            Assert.False(packet.IsValid);
            Assert.Throws<InvalidOperationException>(packet.Ethernet.IpV4.Igmp.ExtractLayer);
        }

        [Fact]
        public void IgmpTooBigQueryRobustnessVariableTest()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(), new IgmpQueryVersion3Layer
            {
                QueryRobustnessVariable = 255
            }));
        }

        [Fact]
        public void DifferentIgmpSimpleLayersTest()
        {
            IgmpVersion1PlusSimpleLayer layer1 = new IgmpQueryVersion1Layer
            {
                GroupAddress = new IpV4Address("1.2.3.4")
            };
            IgmpVersion1PlusSimpleLayer layer2 = new IgmpQueryVersion2Layer
            {
                GroupAddress = new IpV4Address("1.2.3.4"),
                MaxResponseTime = TimeSpan.FromMinutes(55)
            };
            Assert.False(layer1.Equals(layer2));
        }

        [Fact]
        public void IgmpGroupRecordConstructorNullTest()
        {
            Assert.Throws<ArgumentNullException>(() => new IgmpGroupRecord(IgmpRecordType.FilterModeChangeToExclude, IpV4Address.Zero, new IpV4Address[0], null));
        }

        [Fact]
        public void IgmpTooLong()
        {
            Packet packet = PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(), new IgmpQueryVersion1Layer());
            Assert.True(packet.IsValid);

            byte[] invalidPacketBuffer = packet.Buffer.ToArray();
            invalidPacketBuffer[EthernetDatagram.HeaderLengthValue + IpV4Datagram.HeaderMinimumLength] = (byte)IgmpMessageType.MulticastTraceRoute;
            const ushort newCheckSum = 57599;
            invalidPacketBuffer[EthernetDatagram.HeaderLengthValue + IpV4Datagram.HeaderMinimumLength + sizeof(ushort)] = newCheckSum >> 8;
            invalidPacketBuffer[EthernetDatagram.HeaderLengthValue + IpV4Datagram.HeaderMinimumLength + sizeof(ushort) + sizeof(byte)] = newCheckSum & 0xFF;
            Packet invalidPacket = new Packet(invalidPacketBuffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IgmpDatagramIsPrivateForNotCreateGroupRequestVersion0()
        {
            Packet packet = PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(), new IgmpQueryVersion1Layer());
            Assert.True(packet.IsValid);
            Assert.Throws<InvalidOperationException>(() => packet.Ethernet.IpV4.Igmp.CreateGroupRequestCode);
        }

        [Fact]
        public void IgmpDatagramReplyCodeVersion0Reply()
        {
            Packet packet = PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(), new IgmpQueryVersion1Layer());
            Assert.True(packet.IsValid);
            Assert.Throws<InvalidOperationException>(() => packet.Ethernet.IpV4.Igmp.ReplyCode);
        }

        [Fact]
        public void IgmpDatagramRetryInThisManySecondsForReplyCodeThatIsNotRequestPendingRetryInThisManySeconds()
        {
            Packet packet = PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(), new IgmpReplyVersion0Layer());
            Assert.True(packet.IsValid);
            Assert.Throws<InvalidOperationException>(() => packet.Ethernet.IpV4.Igmp.RetryInThisManySeconds);
        }

        [Fact]
        public void IgmpReplyVersion0LayerSetInvalidType()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IgmpReplyVersion0Layer { MessageType = IgmpMessageType.LeaveGroupVersion2 });
        }

        [Fact]
        public void IgmpRequestVersion0LayerSetInvalidType()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IgmpRequestVersion0Layer { MessageType = IgmpMessageType.LeaveGroupVersion2 });
        }
    }
}
