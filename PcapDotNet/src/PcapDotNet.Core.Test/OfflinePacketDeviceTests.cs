using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.TestUtils;
using PcapDotNet.TestUtils;
using Xunit;

namespace PcapDotNet.Core.Test
{
    /// <summary>
    /// Summary description for OfflinePacketDeviceTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    [Collection(nameof(LivePacketDeviceTests))]
    public class OfflinePacketDeviceTests
    {
        private static void TestOpenMultipleTimes(int numTimes, string filename)
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";
            const int NumPackets = 10;
            Packet expectedPacket = _random.NextEthernetPacket(100, SourceMac, DestinationMac);
            PacketDevice device = GetOfflineDevice(NumPackets, expectedPacket, TimeSpan.Zero, Path.GetTempPath() + @"dump.pcap", Path.GetTempPath() + filename);
            for (int j = 0; j != numTimes; ++j)
            {
                using (PacketCommunicator communicator = device.Open())
                {
                    PacketCommunicatorReceiveResult result;
                    Packet actualPacket;
                    for (int i = 0; i != NumPackets; ++i)
                    {
                        result = communicator.ReceivePacket(out actualPacket);
                        Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                        Assert.Equal(expectedPacket, actualPacket);
                        MoreAssert.IsInRange(expectedPacket.Timestamp.AddSeconds(-0.05), expectedPacket.Timestamp.AddSeconds(0.05),
                                             actualPacket.Timestamp);
                    }

                    result = communicator.ReceivePacket(out actualPacket);
                    Assert.Equal(PacketCommunicatorReceiveResult.Eof, result);
                    Assert.Null(actualPacket);
                }
            }
        }

        [Fact]
        public void OpenOfflineMultipleTimes()
        {
            TestOpenMultipleTimes(1000, @"dump.pcap");
        }

        [Fact]
        public void OpenOfflineMultipleTimesUnicode()
        {
            // TODO: Fix so we can go beyond 509 when using unicode filenames. See http://www.winpcap.org/pipermail/winpcap-bugs/2012-December/001547.html
            TestOpenMultipleTimes(100, @"דמפ.pcap");
        }

        [Fact]
        public void GetPacketTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";
            const int NumPackets = 10;

            Packet expectedPacket = _random.NextEthernetPacket(100, SourceMac, DestinationMac);

            using (PacketCommunicator communicator = OpenOfflineDevice(NumPackets, expectedPacket))
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);

                PacketCommunicatorReceiveResult result;
                Packet actualPacket;
                for (int i = 0; i != NumPackets; ++i)
                {
                    result = communicator.ReceivePacket(out actualPacket);
                    Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                    Assert.Equal(expectedPacket, actualPacket);
                    MoreAssert.IsInRange(expectedPacket.Timestamp.AddSeconds(-0.05), expectedPacket.Timestamp.AddSeconds(0.05),
                                            actualPacket.Timestamp);
                }

                result = communicator.ReceivePacket(out actualPacket);
                Assert.Equal(PacketCommunicatorReceiveResult.Eof, result);
                Assert.Null(actualPacket);
            }
        }

        [Fact]
        public void GetSomePacketsTest()
        {
            const int NumPacketsToSend = 100;

            // Normal
            TestGetSomePackets(NumPacketsToSend, NumPacketsToSend, int.MaxValue, PacketCommunicatorReceiveResult.Ok, NumPacketsToSend, 0.05, 0.05);
            TestGetSomePackets(NumPacketsToSend, NumPacketsToSend / 2, int.MaxValue, PacketCommunicatorReceiveResult.Ok, NumPacketsToSend / 2, 0.05, 0.05);

            // Eof
            // ToDo: 'pcap_dispatch' does not return expected value, 0 as undefined behaviour on different plattforms
            TestGetSomePackets(NumPacketsToSend, 0, int.MaxValue, PacketCommunicatorReceiveResult.Eof, NumPacketsToSend, 0.05, 0.05);
            TestGetSomePackets(NumPacketsToSend, -1, int.MaxValue, PacketCommunicatorReceiveResult.Eof, NumPacketsToSend, 0.05, 0.05);
            TestGetSomePackets(NumPacketsToSend, NumPacketsToSend + 1, int.MaxValue, PacketCommunicatorReceiveResult.Eof, NumPacketsToSend, 0.05, 0.05);

            // Break loop
            TestGetSomePackets(NumPacketsToSend, NumPacketsToSend, NumPacketsToSend / 2, PacketCommunicatorReceiveResult.Ok, NumPacketsToSend / 2, 0.05, 0.05);
            TestGetSomePackets(NumPacketsToSend, NumPacketsToSend, 0, PacketCommunicatorReceiveResult.BreakLoop, 0, 0.05, 0.05);
        }

        private const int GetPacketsTest_NumPacketsToSend = 100;

        [Theory]
        // Normal
        [InlineData(GetPacketsTest_NumPacketsToSend, GetPacketsTest_NumPacketsToSend, int.MaxValue, PacketCommunicatorReceiveResult.Ok, GetPacketsTest_NumPacketsToSend, 0.05, 0.05)]
        [InlineData(GetPacketsTest_NumPacketsToSend, GetPacketsTest_NumPacketsToSend / 2, int.MaxValue, PacketCommunicatorReceiveResult.Ok, GetPacketsTest_NumPacketsToSend / 2, 0.05, 0.05)]
        // Eof
        [InlineData(GetPacketsTest_NumPacketsToSend, 0, int.MaxValue, PacketCommunicatorReceiveResult.Eof, GetPacketsTest_NumPacketsToSend, 0.05, 0.05)]
        [InlineData(GetPacketsTest_NumPacketsToSend, -1, int.MaxValue, PacketCommunicatorReceiveResult.Eof, GetPacketsTest_NumPacketsToSend, 0.05, 0.05)]
        [InlineData(GetPacketsTest_NumPacketsToSend, GetPacketsTest_NumPacketsToSend + 1, int.MaxValue, PacketCommunicatorReceiveResult.Eof, GetPacketsTest_NumPacketsToSend, 0.05, 0.05)]
        [InlineData(0, -1, int.MaxValue, PacketCommunicatorReceiveResult.Eof, 0, 0.05, 0.05)]
        // Break loop
        [InlineData(GetPacketsTest_NumPacketsToSend, GetPacketsTest_NumPacketsToSend, GetPacketsTest_NumPacketsToSend / 2, PacketCommunicatorReceiveResult.BreakLoop, GetPacketsTest_NumPacketsToSend / 2, 0.05, 0.05)]
        [InlineData(GetPacketsTest_NumPacketsToSend, GetPacketsTest_NumPacketsToSend, 0, PacketCommunicatorReceiveResult.BreakLoop, 0, 0.05, 0.05)]
        public async Task GetPacketsTest(int numPacketsToSend, int numPacketsToGet, int numPacketsToBreakLoop,
                                               PacketCommunicatorReceiveResult expectedResult, int expectedNumPackets,
                                               double expectedMinSeconds, double expectedMaxSeconds)
        {
            string testDescription = "NumPacketsToSend=" + numPacketsToSend + ". NumPacketsToGet=" + numPacketsToGet +
                         ". NumPacketsToBreakLoop=" + numPacketsToBreakLoop;

            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            Packet expectedPacket = _random.NextEthernetPacket(24, SourceMac, DestinationMac);

            using (PacketCommunicator communicator = OpenOfflineDevice(numPacketsToSend, expectedPacket))
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);

                if (numPacketsToBreakLoop == 0)
                    communicator.Break();
                PacketHandler handler = new PacketHandler(expectedPacket, expectedMinSeconds, expectedMaxSeconds, communicator, numPacketsToBreakLoop);

                PacketCommunicatorReceiveResult result = PacketCommunicatorReceiveResult.None;
                var task = Task.Run(delegate ()
                {
                    result = communicator.ReceivePackets(numPacketsToGet, handler.Handle);
                }, TestContext.Current.CancellationToken);
                var delay = Task.Delay(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
                await Task.WhenAny(task, delay);

                Assert.True(expectedResult == result, testDescription);
                Assert.Equal(expectedNumPackets, handler.NumPacketsHandled);
            }
        }

        [Fact]
        public void StatisticsModeErrorTest()
        {
            using (PacketCommunicator communicator = OpenOfflineDevice())
            {
                Assert.Throws<InvalidOperationException>(() => communicator.Mode = PacketCommunicatorMode.Statistics);
            }
        }

        [Fact]
        public void SetNonBlockTest()
        {
            using (PacketCommunicator communicator = OpenOfflineDevice())
            {
                Assert.False(communicator.NonBlocking);
                Assert.Throws<InvalidOperationException>(() => communicator.NonBlocking = false);
            }
        }

        [Fact]
        public void GetTotalStatisticsErrorTest()
        {
            using (PacketCommunicator communicator = OpenOfflineDevice())
            {
                Assert.Throws<InvalidOperationException>(() => communicator.TotalStatistics);
            }
        }

        [Fact]
        public void OpenInvalidFileTest()
        {
            Assert.Throws<InvalidOperationException>(() => new OfflinePacketDevice("myinvalidfile").Open());
        }

        [Fact]
        public void OpenNullFilenameTest()
        {
            Assert.Throws<ArgumentNullException>(() => new OfflinePacketDevice(null).Open());
        }

        [Fact]
        public void SendPacketErrorTest()
        {
            using (PacketCommunicator communicator = OpenOfflineDevice())
            {
                Assert.Throws<InvalidOperationException>(() => communicator.SendPacket(_random.NextEthernetPacket(100)));
            }
        }

        [Fact]
        public void SetKernelBufferSizeErrorTest()
        {
            using (PacketCommunicator communicator = OpenOfflineDevice())
            {
                Assert.Throws<InvalidOperationException>(() => communicator.SetKernelBufferSize(1024 * 1024));
            }
        }

        [Fact]
        public void SetlKernelMinimumBytesToCopyErrorTest()
        {
            using (PacketCommunicator communicator = OpenOfflineDevice())
            {
                Assert.Throws<InvalidOperationException>(() => communicator.SetKernelMinimumBytesToCopy(1024));
            }
        }

        [Fact]
        public void SetSamplingMethodOneEveryNTest()
        {
            Packet expectedPacket = _random.NextEthernetPacket(100);
            using (PacketCommunicator communicator = OpenOfflineDevice(101, expectedPacket))
            {
                communicator.SetSamplingMethod(new SamplingMethodOneEveryCount(10));
                PacketCommunicatorReceiveResult result;
                Packet packet;
                for (int i = 0; i != 10; ++i)
                {
                    result = communicator.ReceivePacket(out packet);
                    Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                    Assert.Equal(expectedPacket, packet);
                }
                result = communicator.ReceivePacket(out packet);
                Assert.Equal(PacketCommunicatorReceiveResult.Eof, result);
                Assert.Null(packet);
            }
        }

        [Fact]
        public void SetSamplingMethodFirstAfterIntervalTest()
        {
            const int NumPackets = 10;
            
            Packet expectedPacket = _random.NextEthernetPacket(100);
            using (PacketCommunicator communicator = OpenOfflineDevice(NumPackets, expectedPacket, TimeSpan.FromSeconds(1)))
            {
                communicator.SetSamplingMethod(new SamplingMethodFirstAfterInterval(TimeSpan.FromSeconds(2)));

                PacketCommunicatorReceiveResult result;
                Packet packet;
                for (int i = 0; i != 5; ++i)
                {
                    result = communicator.ReceivePacket(out packet);
                    Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                    Assert.Equal(expectedPacket, packet);
                    DateTime expectedTimestamp = expectedPacket.Timestamp.AddSeconds(i * 2);
                    MoreAssert.IsInRange(expectedTimestamp.AddSeconds(-0.01), expectedTimestamp.AddSeconds(0.01), packet.Timestamp);
                }
                result = communicator.ReceivePacket(out packet);
                Assert.Equal(PacketCommunicatorReceiveResult.Eof, result);
                Assert.Null(packet);
            }
        }

        [Fact]
        public void DumpToBadFileTest()
        {
            Assert.Throws<InvalidOperationException>(() => OpenOfflineDevice(10, _random.NextEthernetPacket(100), TimeSpan.Zero, "??"));
        }
        
        [Fact]
        public void EmptyNameTest()
        {
            Assert.Throws<InvalidOperationException>(() => OpenOfflineDevice(10, _random.NextEthernetPacket(100), TimeSpan.Zero, string.Empty));
        }

        [Fact]
        public void ReadWriteIso88591FilenameTest()
        {
            const string DumpFilename = "abc_\u00F9\u00E8.pcap";
            const int NumPackets = 10;
            Packet expectedPacket = PacketBuilder.Build(DateTime.Now, new EthernetLayer { EtherType = EthernetType.IpV4 });
            using (PacketCommunicator communicator = OpenOfflineDevice(NumPackets, expectedPacket, TimeSpan.FromSeconds(0.1), DumpFilename))
            {
                for (int i = 0; i != NumPackets; ++i)
                {
                    Packet actualPacket;
                    Assert.Equal(PacketCommunicatorReceiveResult.Ok, communicator.ReceivePacket(out actualPacket));
                    Assert.Equal(expectedPacket, actualPacket);
                }
            }

            Assert.True(File.Exists(DumpFilename), string.Format("File {0} doesn't exist", DumpFilename));
        }

        // TODO: Add this test once Dumping to files with Unicode filenames is supported. See http://www.winpcap.org/pipermail/winpcap-users/2011-February/004273.html
//        [Fact]
//        public void ReadWriteUnicodeFilenameTest()
//        {
//            const string DumpFilename = "abc_\u00F9_\u05D0\u05D1\u05D2.pcap";
//            const int NumPackets = 10;
//            Packet expectedPacket = PacketBuilder.Build(DateTime.Now, new EthernetLayer {EtherType = EthernetType.IpV4});
//            using (PacketCommunicator communicator = OpenOfflineDevice(NumPackets, expectedPacket, TimeSpan.FromSeconds(0.1), DumpFilename))
//            {
//                for (int i = 0; i != NumPackets; ++i)
//                {
//                    Packet actualPacket;
//                    Assert.Equal(PacketCommunicatorReceiveResult.Ok, communicator.ReceivePacket(out actualPacket));
//                    Assert.Equal(expectedPacket, actualPacket);
//                }
//            }
//
//            Assert.True(File.Exists(DumpFilename), "File " + DumpFilename, " doesn't exist");
//        }

        [Fact]
        public void ReadUnicodeFilenameTest()
        {
            const string ReadUnicodeFilename = "abc_\u00F9_\u05D0\u05D1\u05D2.pcap";
            const string DumpAsciiFilename = "abc.pcap";
            const int NumPackets = 10;
            Packet expectedPacket = PacketBuilder.Build(DateTime.Now, new EthernetLayer { EtherType = EthernetType.IpV4 });
            using (PacketCommunicator communicator = OpenOfflineDevice(NumPackets, expectedPacket, TimeSpan.FromSeconds(0.1), DumpAsciiFilename, ReadUnicodeFilename))
            {
                for (int i = 0; i != NumPackets; ++i)
                {
                    Packet actualPacket;
                    Assert.Equal(PacketCommunicatorReceiveResult.Ok, communicator.ReceivePacket(out actualPacket));
                    Assert.Equal(expectedPacket, actualPacket);
                }
            }

            Assert.True(File.Exists(ReadUnicodeFilename), string.Format("File {0} doesn't exist", ReadUnicodeFilename));
        }


        [Fact]
        public void ReadNonExistingUnicodeFilenameTest()
        {
            const string ReadUnicodeFilename = "abc_non_existing_\u00F9_\u05D0\u05D1\u05D2.pcap";
            OfflinePacketDevice device = new OfflinePacketDevice(ReadUnicodeFilename);
            Assert.Throws<InvalidOperationException>(() => device.Open());
        }

        private static void TestGetSomePackets(int numPacketsToSend, int numPacketsToGet, int numPacketsToBreakLoop,
                                               PacketCommunicatorReceiveResult expectedResult, int expectedNumPackets,
                                               double expectedMinSeconds, double expectedMaxSeconds)
        {
            string testDescription = "NumPacketsToSend=" + numPacketsToSend + ". NumPacketsToGet=" + numPacketsToGet +
                                     ". NumPacketsToBreakLoop=" + numPacketsToBreakLoop;

            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            Packet expectedPacket = _random.NextEthernetPacket(100, SourceMac, DestinationMac);

            using (PacketCommunicator communicator = OpenOfflineDevice(numPacketsToSend, expectedPacket))
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);

                if (numPacketsToBreakLoop == 0)
                    communicator.Break();
                PacketHandler handler = new PacketHandler(expectedPacket, expectedMinSeconds, expectedMaxSeconds, communicator, numPacketsToBreakLoop);

                int numPacketsGot;
                PacketCommunicatorReceiveResult result = communicator.ReceiveSomePackets(out numPacketsGot, numPacketsToGet, handler.Handle);
                Assert.Equal(expectedResult, result);
                Assert.True(expectedNumPackets == numPacketsGot, "NumPacketsGot. Test: " + testDescription);
                Assert.True(expectedNumPackets == handler.NumPacketsHandled, "NumPacketsHandled. Test: " + testDescription);
            }
        }

        public static OfflinePacketDevice GetOfflineDevice(int numPackets, Packet packet)
        {
            return GetOfflineDevice(numPackets, packet, TimeSpan.Zero);
        }

        public static OfflinePacketDevice GetOfflineDevice(int numPackets, Packet packet, TimeSpan intervalBetweenPackets)
        {
            return GetOfflineDevice(numPackets, packet, intervalBetweenPackets, Path.Combine(Path.GetTempPath(), "dump.pcap"));
        }

        public static OfflinePacketDevice GetOfflineDevice(int numPackets, Packet packet, TimeSpan intervalBetweenPackets, string dumpFilename, string readFilename = null)
        {
            if (readFilename == null)
                readFilename = dumpFilename;
            PacketCommunicator communicator;
            using (communicator = LivePacketDeviceTests.OpenLiveDevice())
            {
                using (PacketDumpFile dumpFile = communicator.OpenDump(dumpFilename))
                {
                    int lastPosition = 0;
                    for (int i = 0; i != numPackets; ++i)
                    {
                        if (intervalBetweenPackets != TimeSpan.Zero && i != 0)
                        {
                            DateTime timestamp = packet.Timestamp;
                            timestamp = timestamp.Add(intervalBetweenPackets);
                            packet = new Packet(packet.Buffer, timestamp, packet.DataLink);
                        }
                        dumpFile.Dump(packet);
                        MoreAssert.IsBigger(lastPosition, dumpFile.Position);
                        lastPosition = dumpFile.Position;
                        dumpFile.Flush();
                    }
                }
            }

            if (readFilename != dumpFilename)
            {
                if (File.Exists(readFilename))
                    File.Delete(readFilename);
                File.Move(dumpFilename, readFilename);
            }

            OfflinePacketDevice device = new OfflinePacketDevice(readFilename);
            Assert.Empty(device.Addresses);
            Assert.Equal(string.Empty, device.Description);
            Assert.Equal(DeviceAttributes.None, device.Attributes);
            Assert.Equal(readFilename, device.Name);

            return device;
        }

        public static PacketCommunicator OpenOfflineDevice()
        {
            return OpenOfflineDevice(10, _random.NextEthernetPacket(100));
        }

        public static PacketCommunicator OpenOfflineDevice(int numPackets, Packet packet)
        {
            return OpenOfflineDevice(numPackets, packet, TimeSpan.Zero);
        }

        public static PacketCommunicator OpenOfflineDevice(int numPackets, Packet packet, TimeSpan intervalBetweenPackets)
        {
            return OpenOfflineDevice(numPackets, packet, intervalBetweenPackets, Path.Combine(Path.GetTempPath() + @"dump.pcap"));
        }

        private static PacketCommunicator OpenOfflineDevice(int numPackets, Packet packet, TimeSpan intervalBetweenPackets, string dumpFilename, string readFilename = null)
        {
            IPacketDevice device = GetOfflineDevice(numPackets, packet, intervalBetweenPackets, dumpFilename, readFilename);
            PacketCommunicator communicator = device.Open();
            try
            {
                MoreAssert.AreSequenceEqual(new[] {DataLinkKind.Ethernet}.Select(kind => new PcapDataLink(kind)), communicator.SupportedDataLinks);
                Assert.Equal(DataLinkKind.Ethernet, communicator.DataLink.Kind);
                Assert.Equal("EN10MB (Ethernet)", communicator.DataLink.ToString());
                Assert.Equal(communicator.DataLink, new PcapDataLink(communicator.DataLink.Name));
                Assert.True(communicator.IsFileSystemByteOrder);
                Assert.Equal(PacketCommunicatorMode.Capture, communicator.Mode);
                Assert.False(communicator.NonBlocking);
                Assert.Equal(PacketDevice.DefaultSnapshotLength, communicator.SnapshotLength);
                Assert.Equal(2, communicator.FileMajorVersion);
                Assert.Equal(4, communicator.FileMinorVersion);
                return communicator;
            }
            catch (Exception)
            {
                communicator.Dispose();
                throw;
            }
        }

        private static readonly Random _random = new Random();
    }
}
