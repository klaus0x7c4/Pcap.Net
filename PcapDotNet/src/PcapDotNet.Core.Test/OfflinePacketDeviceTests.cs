using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.TestUtils;
using PcapDotNet.TestUtils;
using Xunit;
using Xunit.Extensions;
using TaskExtensions = PcapDotNet.Core.Extensions.TaskExtensions;

namespace PcapDotNet.Core.Test
{
    /// <summary>
    /// Summary description for OfflinePacketDeviceTests
    /// </summary>
    [ExcludeFromCodeCoverage]
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

#if !REAL
        private readonly TestablePcapPal _pal;

        public OfflinePacketDeviceTests()
        {
            _pal = TestablePcapPal.UseTestPal();
        }
#endif

        [Fact]
        public void OpenOfflineMultipleTimes()
        {
            TestOpenMultipleTimes(1000, @"dump.pcap");
        }

        [Fact]
        public void OpenOfflineMultipleTimesUnicode()
        {
            TestOpenMultipleTimes(100, @"דמפ.pcap");
        }
#if NETCOREAPP2_0_OR_GREATER
        [Fact]
        public void LongUnicode_OpenOfflineMultipleTimes_NoError()
        {
            TestOpenMultipleTimes(100, @"דמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפדמפ.pcap");
        }
#endif
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

        public static IEnumerable<object[]> GetSomePacketsTestData
        {
            get
            {
                const int NumPacketsToSend = 100;

                // Normal
                yield return new object[] { NumPacketsToSend, NumPacketsToSend, int.MaxValue, PacketCommunicatorReceiveResult.Ok, NumPacketsToSend, 0.05, 0.05 };
                yield return new object[] { NumPacketsToSend, NumPacketsToSend / 2, int.MaxValue, PacketCommunicatorReceiveResult.Ok, NumPacketsToSend / 2, 0.05, 0.05 };
                // Eof, for all npcap behaves differently! winpcap returns 0, npcap returns 100
                yield return new object[] { NumPacketsToSend, 0, int.MaxValue, PacketCommunicatorReceiveResult.Eof, NumPacketsToSend, 0.05, 0.05 };
                yield return new object[] { NumPacketsToSend, -1, int.MaxValue, PacketCommunicatorReceiveResult.Eof, NumPacketsToSend, 0.05, 0.05 };
                yield return new object[] { NumPacketsToSend, NumPacketsToSend + 1, int.MaxValue, PacketCommunicatorReceiveResult.Eof, NumPacketsToSend, 0.05, 0.05 };
                // Break loop
                yield return new object[] { NumPacketsToSend, NumPacketsToSend, NumPacketsToSend / 2, PacketCommunicatorReceiveResult.Ok, NumPacketsToSend / 2, 0.05, 0.05 };
                yield return new object[] { NumPacketsToSend, NumPacketsToSend, 0, PacketCommunicatorReceiveResult.BreakLoop, 0, 0.05, 0.05 };
            }
        }

        [Theory]
#if NETCOREAPP2_0_OR_GREATER
        [MemberData
#else
        [PropertyData
#endif
            (nameof(GetSomePacketsTestData))]
        public void GetSomePacketsTest_NpCap(int numPacketsToSend, int numPacketsToGet, int numPacketsToBreakLoop,
            PacketCommunicatorReceiveResult expectedResult, int expectedNumPackets, double expectedMinSeconds, double expectedMaxSeconds)
        {
            TestGetSomePackets(numPacketsToSend, numPacketsToGet, numPacketsToBreakLoop, expectedResult, expectedNumPackets, expectedMinSeconds, expectedMaxSeconds);
        }
#if !REAL // prevent duplicate execute
        [Theory]
#if NETCOREAPP2_0_OR_GREATER
        [MemberData
#else
        [PropertyData
#endif
            (nameof(GetSomePacketsTestData))]
        public void GetSomePacketsTest_WinPcap(int numPacketsToSend, int numPacketsToGet, int numPacketsToBreakLoop,
            PacketCommunicatorReceiveResult expectedResult, int expectedNumPackets, double expectedMinSeconds, double expectedMaxSeconds)
        {
            _pal.SetWinPcapBehavior();
            TestGetSomePackets(numPacketsToSend, numPacketsToGet, numPacketsToBreakLoop, expectedResult, expectedNumPackets, expectedMinSeconds, expectedMaxSeconds);
        }
#endif
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
        public void GetPacketsTest(int numPacketsToSend, int numPacketsToGet, int numPacketsToBreakLoop,
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
                var task = Task.Factory.StartNew(() =>
                {
                    result = communicator.ReceivePackets(numPacketsToGet, handler.Handle);
                });
                var delay = TaskExtensions.Delay(TimeSpan.FromSeconds(5));
                Task.WaitAny(task, delay);

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
#if !REAL // prevent duplicate execute
        [Fact]
        public void WinPcap_SetNonBlockTest()
        {
            _pal.SetWinPcapBehavior();
            using (PacketCommunicator communicator = OpenOfflineDevice())
            {
                Assert.False(communicator.NonBlocking);
                communicator.NonBlocking = false;
                Assert.False(communicator.NonBlocking);
                communicator.NonBlocking = true;
                Assert.False(communicator.NonBlocking);
            }
        }
#endif
        [Fact] // set nonblocking is not supported in npcap, workaround is used to catch
        public void Npcap_SetNonBlockTest()
        {
            using (PacketCommunicator communicator = OpenOfflineDevice())
            {
                Assert.False(communicator.NonBlocking);
                communicator.NonBlocking = false;
                Assert.False(communicator.NonBlocking);
                communicator.NonBlocking = true;
                Assert.False(communicator.NonBlocking);
            }
        }
#if REAL // only testable on real OfflinePacketCommunicator
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
#endif
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
        // fails on REAL unix because no exception
        [Fact]
        public void SetlKernelMinimumBytesToCopyErrorTest()
        {
            using (PacketCommunicator communicator = OpenOfflineDevice())
            {
                Assert.Throws<InvalidOperationException>(() => communicator.SetKernelMinimumBytesToCopy(1024));
            }
        }

        // sampling pcap files not supported in npcap, see savefile.c for change in pcapint_offline_read (before pcap_offline_read)
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

        // sampling pcap files not supported in npcap, see savefile.c for change in pcapint_offline_read (before pcap_offline_read)
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
#if REAL // only testable on real OfflinePacketCommunicator
        // fails on REAL unix because no exception
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
#endif
        // this test fails only with winpcap, with specific OEM codepages (i.e. 437)
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

        // this test fails only with winpcap
        [Fact]
        public void ReadWriteUnicodeFilenameTest()
        {
            const string DumpFilename = "abc_\u00F9_\u05D0\u05D1\u05D2.pcap";
            const int NumPackets = 10;
            var expectedPacket = PacketBuilder.Build(DateTime.Now, new EthernetLayer { EtherType = EthernetType.IpV4 });
            using (PacketCommunicator communicator = OpenOfflineDevice(NumPackets, expectedPacket, TimeSpan.FromSeconds(0.1), DumpFilename))
            {
                for (int i = 0; i != NumPackets; ++i)
                {
                    Assert.Equal(PacketCommunicatorReceiveResult.Ok, communicator.ReceivePacket(out var actualPacket));
                    Assert.Equal(expectedPacket, actualPacket);
                }
            }

            Assert.True(File.Exists(DumpFilename), $"File {DumpFilename} doesn't exist");
        }

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
#if REAL
            OfflinePacketDevice device = new OfflinePacketDevice(ReadUnicodeFilename);
#else
            var device = new TestableOfflinePacketDevice(ReadUnicodeFilename);
#endif
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

        public static PacketDevice GetOfflineDevice(int numPackets, Packet packet, TimeSpan intervalBetweenPackets, string dumpFilename, string readFilename = null)
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
#if REAL
            OfflinePacketDevice device = new OfflinePacketDevice(readFilename);
            Assert.Empty(device.Addresses);
            Assert.Empty(device.Description);
            Assert.Equal(DeviceAttributes.None, device.Attributes);
            Assert.Equal(readFilename, device.Name);
#else
            var device = new TestableOfflinePacketDevice(readFilename);
#endif
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
            return OpenOfflineDevice(numPackets, packet, intervalBetweenPackets, Path.Combine(Path.GetTempPath(), @"dump.pcap"));
        }

        private static PacketCommunicator OpenOfflineDevice(int numPackets, Packet packet, TimeSpan intervalBetweenPackets, string dumpFilename, string readFilename = null)
        {
            IPacketDevice device = GetOfflineDevice(numPackets, packet, intervalBetweenPackets, dumpFilename, readFilename);
            PacketCommunicator communicator = device.Open();
            try
            {
#if REAL
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
#endif
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
