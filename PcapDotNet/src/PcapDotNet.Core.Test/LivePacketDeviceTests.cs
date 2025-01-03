using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using PcapDotNet.Base;
using PcapDotNet.Core.Extensions;
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
    /// Summary description for LivePacketDeviceTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class LivePacketDeviceTests
    {
#if !REAL
        private readonly TestablePcapPal _pal;

        public LivePacketDeviceTests()
        {
            _pal = TestablePcapPal.UseTestPal();
        }
#endif

        [Fact]
        public void SendAndReceivePacketTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";
            const int NumPacketsToSend = 10;

            using (PacketCommunicator communicator = OpenLiveDevice(100))
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);

                Packet packet;
                DateTime startWaiting = DateTime.Now;
                PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                DateTime finishedWaiting = DateTime.Now;

                Assert.Equal(PacketCommunicatorReceiveResult.Timeout, result);
                Assert.Equal<uint>(0, communicator.TotalStatistics.PacketsCaptured);
                MoreAssert.IsInRange(TimeSpan.FromSeconds(0.99), TimeSpan.FromSeconds(1.075), finishedWaiting - startWaiting);

                Packet sentPacket = _random.NextEthernetPacket(200, 300, SourceMac, DestinationMac);

                DateTime startSendingTime = DateTime.Now;

                for (int i = 0; i != NumPacketsToSend; ++i)
                {
                    communicator.SendPacket(sentPacket);
                }

                DateTime endSendingTime = DateTime.Now;

                for (int i = 0; i != NumPacketsToSend; ++i)
                {
                    result = communicator.ReceivePacket(out packet);

                    Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                    Assert.Equal(100, packet.Length);
                    Assert.Equal<uint>(200, packet.OriginalLength);
                    MoreAssert.IsInRange(startSendingTime - TimeSpan.FromSeconds(1), endSendingTime + TimeSpan.FromSeconds(30), packet.Timestamp);
                }
                Assert.Equal<uint>(NumPacketsToSend, communicator.TotalStatistics.PacketsCaptured);
            }
        }

        [Fact]
        public void SendNullPacketTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.Throws<ArgumentNullException>(() => communicator.SendPacket(null));
            }
        }

        [Fact]
        public void SetNullFilterTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.Throws<ArgumentNullException>(() => communicator.SetFilter(null as BerkeleyPacketFilter));
            }
        }

        [Fact]
        public void SetNullSamplingMethodTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.Throws<ArgumentNullException>(() => communicator.SetSamplingMethod(null));
            }
        }

        private const int ReceiveSomePacketsTest_NumPacketsToSend = 100;
        private const int ReceiveSomePacketsTest_PacketSize = 100;

        [Theory]
        // Test normal mode
        [InlineData(0, 0, int.MaxValue, ReceiveSomePacketsTest_PacketSize, false, PacketCommunicatorReceiveResult.Ok, 0, 1, 1.06)]
        [InlineData(ReceiveSomePacketsTest_NumPacketsToSend, ReceiveSomePacketsTest_NumPacketsToSend, int.MaxValue, ReceiveSomePacketsTest_PacketSize, false, PacketCommunicatorReceiveResult.Ok, ReceiveSomePacketsTest_NumPacketsToSend, 0, 0.02)]
        [InlineData(ReceiveSomePacketsTest_NumPacketsToSend, 0, int.MaxValue, ReceiveSomePacketsTest_PacketSize, false, PacketCommunicatorReceiveResult.Ok, ReceiveSomePacketsTest_NumPacketsToSend, 0, 0.02)]
        [InlineData(ReceiveSomePacketsTest_NumPacketsToSend, -1, int.MaxValue, ReceiveSomePacketsTest_PacketSize, false, PacketCommunicatorReceiveResult.Ok, ReceiveSomePacketsTest_NumPacketsToSend, 0, 0.028)]
        [InlineData(ReceiveSomePacketsTest_NumPacketsToSend, ReceiveSomePacketsTest_NumPacketsToSend + 1, int.MaxValue, ReceiveSomePacketsTest_PacketSize, false, PacketCommunicatorReceiveResult.Ok, ReceiveSomePacketsTest_NumPacketsToSend, 0, 0.031)]
        // Test non blocking
        [InlineData(0, 0, int.MaxValue, ReceiveSomePacketsTest_PacketSize, true, PacketCommunicatorReceiveResult.Ok, 0, 0, 0.02)]
        [InlineData(ReceiveSomePacketsTest_NumPacketsToSend, ReceiveSomePacketsTest_NumPacketsToSend, int.MaxValue, ReceiveSomePacketsTest_PacketSize, true, PacketCommunicatorReceiveResult.Ok, ReceiveSomePacketsTest_NumPacketsToSend, 0, 0.02)]
        // Test break loop
        [InlineData(ReceiveSomePacketsTest_NumPacketsToSend, ReceiveSomePacketsTest_NumPacketsToSend, ReceiveSomePacketsTest_NumPacketsToSend / 2, ReceiveSomePacketsTest_PacketSize, false, PacketCommunicatorReceiveResult.Ok, ReceiveSomePacketsTest_NumPacketsToSend / 2, 0, 0.02)]
        [InlineData(ReceiveSomePacketsTest_NumPacketsToSend, ReceiveSomePacketsTest_NumPacketsToSend, ReceiveSomePacketsTest_NumPacketsToSend / 2, ReceiveSomePacketsTest_PacketSize, true, PacketCommunicatorReceiveResult.Ok, ReceiveSomePacketsTest_NumPacketsToSend / 2, 0, 0.02)]
        [InlineData(ReceiveSomePacketsTest_NumPacketsToSend, ReceiveSomePacketsTest_NumPacketsToSend, 0, ReceiveSomePacketsTest_PacketSize, false, PacketCommunicatorReceiveResult.BreakLoop, 0, 0, 0.02)]
        public void ReceiveSomePacketsTest(int numPacketsToSend, int numPacketsToGet, int numPacketsToBreakLoop, int packetSize, bool nonBlocking,
                                                   PacketCommunicatorReceiveResult expectedResult, int expectedNumPackets, double expectedMinSeconds, double expectedMaxSeconds)
        {
            string testDescription = "NumPacketsToSend=" + numPacketsToSend + ". NumPacketsToGet=" + numPacketsToGet +
                                     ". NumPacketsToBreakLoop=" + numPacketsToBreakLoop + ". PacketSize=" + packetSize +
                                     ". NonBlocking=" + nonBlocking;

            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            Packet packetToSend = _random.NextEthernetPacket(packetSize, SourceMac, DestinationMac);

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.NonBlocking = nonBlocking;
                Assert.Equal(nonBlocking, communicator.NonBlocking);
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);

                int numPacketsGot;
                for (int i = 0; i != numPacketsToSend; ++i)
                    communicator.SendPacket(packetToSend);

                if (numPacketsToBreakLoop == 0)
                    communicator.Break();

                PacketHandler handler = new PacketHandler(packetToSend, communicator, numPacketsToBreakLoop);
                DateTime startWaiting = DateTime.Now;
                PacketCommunicatorReceiveResult result = communicator.ReceiveSomePackets(out numPacketsGot, numPacketsToGet,
                                                                                         handler.Handle);
                DateTime finishedWaiting = DateTime.Now;

                Assert.Equal(expectedResult, result);
                Assert.True(expectedNumPackets == numPacketsGot, "NumPacketsGot. Test: " + testDescription);
                Assert.True(expectedNumPackets == handler.NumPacketsHandled, "NumPacketsHandled. Test: " + testDescription);
                MoreAssert.IsInRange(expectedMinSeconds, expectedMaxSeconds, (finishedWaiting - startWaiting).TotalSeconds, testDescription);
            }
        }

        private const int ReceivePacketsTest_NumPacketsToSend = 100;
        private const int ReceivePacketsTest_PacketSize = 100;
        // fails on REAL unix because no packets are sent
        [Theory]
        // Normal
        [InlineData(ReceivePacketsTest_NumPacketsToSend, ReceivePacketsTest_NumPacketsToSend, int.MaxValue, 2, ReceivePacketsTest_PacketSize, PacketCommunicatorReceiveResult.Ok, ReceivePacketsTest_NumPacketsToSend, 0, 0.12)]
        // Wait for less packets
        [InlineData(ReceivePacketsTest_NumPacketsToSend, ReceivePacketsTest_NumPacketsToSend / 2, int.MaxValue, 2, ReceivePacketsTest_PacketSize, PacketCommunicatorReceiveResult.Ok, ReceivePacketsTest_NumPacketsToSend / 2, 0, 0.04)]
        // Wait for more packets
        [InlineData(ReceivePacketsTest_NumPacketsToSend, 0, int.MaxValue, 2, ReceivePacketsTest_PacketSize, PacketCommunicatorReceiveResult.None, ReceivePacketsTest_NumPacketsToSend, 2, 2.45)]
        [InlineData(ReceivePacketsTest_NumPacketsToSend, -1, int.MaxValue, 2, ReceivePacketsTest_PacketSize, PacketCommunicatorReceiveResult.None, ReceivePacketsTest_NumPacketsToSend, 2, 2.3)]
        [InlineData(ReceivePacketsTest_NumPacketsToSend, ReceivePacketsTest_NumPacketsToSend + 1, int.MaxValue, 2, ReceivePacketsTest_PacketSize, PacketCommunicatorReceiveResult.None, ReceivePacketsTest_NumPacketsToSend, 2, 2.16)]
        // Break loop
        [InlineData(ReceivePacketsTest_NumPacketsToSend, ReceivePacketsTest_NumPacketsToSend, 0, 2, ReceivePacketsTest_PacketSize, PacketCommunicatorReceiveResult.BreakLoop, 0, 0, 0.027)]
        [InlineData(ReceivePacketsTest_NumPacketsToSend, ReceivePacketsTest_NumPacketsToSend, ReceivePacketsTest_NumPacketsToSend / 2, 2, ReceivePacketsTest_PacketSize, PacketCommunicatorReceiveResult.BreakLoop, ReceivePacketsTest_NumPacketsToSend / 2, 0, 0.046)]
        public void ReceivePacketsTest(int numPacketsToSend, int numPacketsToWait, int numPacketsToBreakLoop, double secondsToWait, int packetSize,
                                           PacketCommunicatorReceiveResult expectedResult, int expectedNumPackets,
                                           double expectedMinSeconds, double expectedMaxSeconds)
        {
            string testDescription = "NumPacketsToSend=" + numPacketsToSend + ". NumPacketsToWait=" + numPacketsToWait +
                                     ". NumPacketsToBreakLoop=" + numPacketsToBreakLoop + ". SecondsToWait=" +
                                     secondsToWait + ". PacketSize=" + packetSize;


            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);

                Packet sentPacket = _random.NextEthernetPacket(packetSize, SourceMac, DestinationMac);

                PacketCommunicatorReceiveResult result = PacketCommunicatorReceiveResult.None;

                for (int i = 0; i != numPacketsToSend; ++i)
                    communicator.SendPacket(sentPacket);

                PacketHandler handler = new PacketHandler(sentPacket, communicator, numPacketsToBreakLoop);

                DateTime startWaiting = DateTime.Now;
                var task = Task.Factory.StartNew(() =>
                {
                    if (numPacketsToBreakLoop == 0)
                        communicator.Break();
                    result = communicator.ReceivePackets(numPacketsToWait, handler.Handle);
                });

                var delay = TaskExtensions.Delay(TimeSpan.FromSeconds(secondsToWait));
                Task.WaitAny(task, delay);
                DateTime finishedWaiting = DateTime.Now;

                Assert.True(expectedResult == result, testDescription);
                Assert.Equal(expectedNumPackets, handler.NumPacketsHandled);
                MoreAssert.IsInRange(expectedMinSeconds, expectedMaxSeconds, (finishedWaiting - startWaiting).TotalSeconds);
            }
        }

        private const int ReceivePacketsEnumerableTest_NumPacketsToSend = 100;
        private const int ReceivePacketsEnumerableTest_PacketSize = 100;
        // fails on REAL unix because no packets are sent
        [Theory]
        // Normal
        [InlineData(ReceivePacketsEnumerableTest_NumPacketsToSend, ReceivePacketsEnumerableTest_NumPacketsToSend, int.MaxValue, 2, ReceivePacketsEnumerableTest_PacketSize, ReceivePacketsEnumerableTest_NumPacketsToSend, 0, 0.3)]
        // Wait for less packets
        [InlineData(ReceivePacketsEnumerableTest_NumPacketsToSend, ReceivePacketsEnumerableTest_NumPacketsToSend / 2, int.MaxValue, 2, ReceivePacketsEnumerableTest_PacketSize, ReceivePacketsEnumerableTest_NumPacketsToSend / 2, 0, 0.032)]
        // Wait for more packets
        [InlineData(ReceivePacketsEnumerableTest_NumPacketsToSend, -1, int.MaxValue, 2, ReceivePacketsEnumerableTest_PacketSize, ReceivePacketsEnumerableTest_NumPacketsToSend, 2, 2.14)]
        [InlineData(ReceivePacketsEnumerableTest_NumPacketsToSend, ReceivePacketsEnumerableTest_NumPacketsToSend + 1, int.MaxValue, 2, ReceivePacketsEnumerableTest_PacketSize, ReceivePacketsEnumerableTest_NumPacketsToSend, 2, 2.13)]
        // Break loop
        [InlineData(ReceivePacketsEnumerableTest_NumPacketsToSend, ReceivePacketsEnumerableTest_NumPacketsToSend, 0, 2, ReceivePacketsEnumerableTest_PacketSize, 0, 0, 0.051)]
        [InlineData(ReceivePacketsEnumerableTest_NumPacketsToSend, ReceivePacketsEnumerableTest_NumPacketsToSend, ReceivePacketsEnumerableTest_NumPacketsToSend / 2, 2, ReceivePacketsEnumerableTest_PacketSize, ReceivePacketsEnumerableTest_NumPacketsToSend / 2, 0, 0.1)]
        public void ReceivePacketsEnumerableTest(int numPacketsToSend, int numPacketsToWait, int numPacketsToBreakLoop, double secondsToWait,
                                                         int packetSize, int expectedNumPackets, double expectedMinSeconds, double expectedMaxSeconds)
        {
            string testDescription = "NumPacketsToSend=" + numPacketsToSend + ". NumPacketsToWait=" + numPacketsToWait +
                                     ". NumPacketsToBreakLoop=" + numPacketsToBreakLoop + ". SecondsToWait=" +
                                     secondsToWait + ". PacketSize=" + packetSize;


            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);

                Packet sentPacket = _random.NextEthernetPacket(packetSize, SourceMac, DestinationMac);

                for (int i = 0; i != numPacketsToSend; ++i)
                    communicator.SendPacket(sentPacket);

                int actualPacketsReceived = 0;
                DateTime startWaiting = DateTime.Now;
                var task = Task.Factory.StartNew(() =>
                {
                    if (numPacketsToBreakLoop == 0)
                        communicator.Break();
                    IEnumerable<Packet> packets = numPacketsToWait == -1
                                                      ? communicator.ReceivePackets()
                                                      : communicator.ReceivePackets(numPacketsToWait);
                    foreach (Packet packet in packets)
                    {
                        Assert.Equal(sentPacket, packet);
                        ++actualPacketsReceived;
                        if (actualPacketsReceived == numPacketsToBreakLoop)
                            break;
                    }
                });

                var delay = TaskExtensions.Delay(TimeSpan.FromSeconds(secondsToWait));
                Task.WaitAny(task, delay);
                DateTime finishedWaiting = DateTime.Now;

                Assert.True(expectedNumPackets == actualPacketsReceived, testDescription);
                MoreAssert.IsInRange(expectedMinSeconds, expectedMaxSeconds, (finishedWaiting - startWaiting).TotalSeconds, testDescription);
            }
        }
        // fails on REAL unix because no packets are sent
        [Fact]
        public void ReceivePacketsGcCollectTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            const int NumPackets = 2;

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);

                Packet sentPacket = _random.NextEthernetPacket(100, SourceMac, DestinationMac);

                for (int i = 0; i != NumPackets; ++i)
                {
                    communicator.SendPacket(sentPacket);
                }

                PacketCommunicatorReceiveResult result = PacketCommunicatorReceiveResult.None;
                var task = Task.Factory.StartNew(() =>
                {
                    result = communicator.ReceivePackets(NumPackets, delegate
                                                                     {
                                                                         GC.Collect();
                                                                     });
                });

                var delay = TaskExtensions.Delay(TimeSpan.FromSeconds(2));
                Task.WaitAny(task, delay);
                Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
            }
        }
        // fails on REAL unix because no packets are sent
        [Fact]
        public void ReceiveSomePacketsGcCollectTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            const int NumPackets = 2;

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);

                Packet sentPacket = _random.NextEthernetPacket(100, SourceMac, DestinationMac);

                for (int i = 0; i != NumPackets; ++i)
                    communicator.SendPacket(sentPacket);

                int numGot;
                PacketCommunicatorReceiveResult result = communicator.ReceiveSomePackets(out numGot, NumPackets,
                                                                                         delegate
                                                                                         {
                                                                                             GC.Collect();
                                                                                         });
                Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                Assert.Equal(NumPackets, numGot);
            }
        }
        // fails on REAL unix because of not supported pcap_setmode
        [Fact]
        public void ReceiveStatisticsGcCollectTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            const int NumStatistics = 2;

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);
                communicator.Mode = PacketCommunicatorMode.Statistics;

                PacketCommunicatorReceiveResult result = communicator.ReceiveStatistics(NumStatistics, delegate
                                                                                                       {
                                                                                                           GC.Collect();
                                                                                                       });
                Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
            }
        }
        // fails on REAL unix because of not supported pcap_setmode
        [Fact]
        public void ReceiveStatisticsTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";
            const int NumPacketsToSend = 100;
            const int PacketSize = 100;

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.Mode = PacketCommunicatorMode.Statistics;
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);

                Packet sentPacket = _random.NextEthernetPacket(PacketSize, SourceMac, DestinationMac);

                PacketSampleStatistics statistics;
                PacketCommunicatorReceiveResult result = communicator.ReceiveStatistics(out statistics);
                Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                MoreAssert.IsInRange(DateTime.Now.AddSeconds(-1), DateTime.Now.AddSeconds(1), statistics.Timestamp);
                Assert.Equal<ulong>(0, statistics.AcceptedPackets);
                Assert.Equal<ulong>(0, statistics.AcceptedBytes);

                for (int i = 0; i != NumPacketsToSend; ++i)
                    communicator.SendPacket(sentPacket);

                result = communicator.ReceiveStatistics(out statistics);

                Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                MoreAssert.IsInRange(DateTime.Now.AddSeconds(-1), DateTime.Now.AddSeconds(1), statistics.Timestamp);
                Assert.Equal<ulong>(NumPacketsToSend, statistics.AcceptedPackets);
                // Todo check byte statistics. See http://www.winpcap.org/pipermail/winpcap-users/2015-February/004931.html
                Assert.True((ulong)(sentPacket.Length + 12) * NumPacketsToSend == statistics.AcceptedBytes,
                                      "AcceptedBytes. Diff Per Packet: " +
                                      (statistics.AcceptedBytes - (ulong)sentPacket.Length * NumPacketsToSend) /
                                      ((double)NumPacketsToSend));
            }
        }

        private const string GetStatisticsTest_SourceMac = "11:22:33:44:55:66";
        private const string GetStatisticsTest_DestinationMac = "77:88:99:AA:BB:CC";
        private const int GetStatisticsTest_NumPacketsToSend = 100;
        private const int GetStatisticsTest_NumStatisticsToGather = 3;
        private const int GetStatisticsTest_PacketSize = 100;
        // fails on REAL unix because of not supported pcap_setmode
        [Theory]
        // Normal
        [InlineData(GetStatisticsTest_SourceMac, GetStatisticsTest_DestinationMac, GetStatisticsTest_NumPacketsToSend, GetStatisticsTest_NumStatisticsToGather, int.MaxValue, 5, GetStatisticsTest_PacketSize,
                              PacketCommunicatorReceiveResult.Ok, GetStatisticsTest_NumStatisticsToGather, GetStatisticsTest_NumPacketsToSend, GetStatisticsTest_NumStatisticsToGather, GetStatisticsTest_NumStatisticsToGather + 0.16)]
        // Wait for less statistics
        [InlineData(GetStatisticsTest_SourceMac, GetStatisticsTest_DestinationMac, GetStatisticsTest_NumPacketsToSend, GetStatisticsTest_NumStatisticsToGather / 2, int.MaxValue, 5, GetStatisticsTest_PacketSize,
                          PacketCommunicatorReceiveResult.Ok, GetStatisticsTest_NumStatisticsToGather / 2, GetStatisticsTest_NumPacketsToSend, GetStatisticsTest_NumStatisticsToGather / 2, GetStatisticsTest_NumStatisticsToGather / 2 + 0.17)]
        // Wait for more statistics
        [InlineData(GetStatisticsTest_SourceMac, GetStatisticsTest_DestinationMac, GetStatisticsTest_NumPacketsToSend, 0, int.MaxValue, 5.5, GetStatisticsTest_PacketSize,
                          PacketCommunicatorReceiveResult.None, 5, GetStatisticsTest_NumPacketsToSend, 5.5, 5.85)]
        // Break loop
        [InlineData(GetStatisticsTest_SourceMac, GetStatisticsTest_DestinationMac, GetStatisticsTest_NumPacketsToSend, GetStatisticsTest_NumStatisticsToGather, 0, 5, GetStatisticsTest_PacketSize,
                          PacketCommunicatorReceiveResult.BreakLoop, 0, 0, 0, 0.04)]
        [InlineData(GetStatisticsTest_SourceMac, GetStatisticsTest_DestinationMac, GetStatisticsTest_NumPacketsToSend, GetStatisticsTest_NumStatisticsToGather, GetStatisticsTest_NumStatisticsToGather / 2, 5, GetStatisticsTest_PacketSize,
                          PacketCommunicatorReceiveResult.BreakLoop, GetStatisticsTest_NumStatisticsToGather / 2, GetStatisticsTest_NumPacketsToSend, GetStatisticsTest_NumStatisticsToGather / 2, GetStatisticsTest_NumStatisticsToGather / 2 + 0.22)]
        public void GetStatisticsTest(string sourceMac, string destinationMac, int numPacketsToSend, int numStatisticsToGather, int numStatisticsToBreakLoop, double secondsToWait, int packetSize,
                                              PacketCommunicatorReceiveResult expectedResult, int expectedNumStatistics, int expectedNumPackets, double expectedMinSeconds, double expectedMaxSeconds)
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.Mode = PacketCommunicatorMode.Statistics;

                communicator.SetFilter("ether src " + sourceMac + " and ether dst " + destinationMac);

                Packet sentPacket = _random.NextEthernetPacket(packetSize, sourceMac, destinationMac);

                PacketCommunicatorReceiveResult result = PacketCommunicatorReceiveResult.None;
                int numStatisticsGot = 0;
                ulong totalPackets = 0;
                ulong totalBytes = 0;
                for (int i = 0; i != numPacketsToSend; ++i)
                    communicator.SendPacket(sentPacket);

                if (numStatisticsToBreakLoop == 0)
                    communicator.Break();

                DateTime startWaiting = DateTime.Now;
                var task = Task.Factory.StartNew(() =>
                {
                    result = communicator.ReceiveStatistics(numStatisticsToGather,
                                                     delegate (PacketSampleStatistics statistics)
                                                     {
                                                         Assert.NotNull(statistics.ToString());
                                                         totalPackets += statistics.AcceptedPackets;
                                                         totalBytes += statistics.AcceptedBytes;
                                                         ++numStatisticsGot;
                                                         if (numStatisticsGot >= numStatisticsToBreakLoop)
                                                             communicator.Break();
                                                     });
                });

                var delay = TaskExtensions.Delay(TimeSpan.FromSeconds(secondsToWait));
                Task.WaitAny(task, delay);
                DateTime finishedWaiting = DateTime.Now;

                Assert.Equal(expectedResult, result);
                Assert.Equal(expectedNumStatistics, numStatisticsGot);
                Assert.Equal((ulong)expectedNumPackets, totalPackets);
                Assert.Equal(numStatisticsToBreakLoop == 0 ? 0 :(ulong)(numPacketsToSend * (sentPacket.Length + 12)), totalBytes);
                MoreAssert.IsInRange(expectedMinSeconds, expectedMaxSeconds, (finishedWaiting - startWaiting).TotalSeconds);
            }
        }

        [Fact]
        public void GetStatisticsOnCaptureModeErrorTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                PacketSampleStatistics statistics;
                Assert.Throws<InvalidOperationException>(() => communicator.ReceiveStatistics(out statistics));
            }
        }
        // fails on REAL unix because of not supported pcap_setmode
        [Fact]
        public void GetPacketOnStatisticsModeErrorTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.Mode = PacketCommunicatorMode.Statistics;
                Packet packet;
                Assert.Throws<InvalidOperationException>(() => communicator.ReceivePacket(out packet));
            }
        }
        // fails on REAL unix because sampling not supported
        [Fact]
        public void SetInvalidModeErrorTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.Throws<InvalidOperationException>(() => communicator.Mode = (PacketCommunicatorMode)(-99));
            }
        }

        // this test is removed for now since it doens't throw an exception for such big value
        //        [Fact]
        //        public void SetBigKernelBufferSizeErrorTest()
        //        {
        //            using (PacketCommunicator communicator = OpenLiveDevice())
        //            {
        //                Assert.Throws<InvalidOperationException>(() => communicator.SetKernelBufferSize(1024 * 1024 * 1024));
        //            }
        //        }
        // fails for npcap because handling the buffer differently
        [Fact]
        public void SetSmallKernelBufferSizeGetPacketErrorTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);
                communicator.SetKernelBufferSize(10);
                Packet packet = _random.NextEthernetPacket(100, SourceMac, DestinationMac);
                communicator.SendPacket(packet);
                Assert.Throws<InvalidOperationException>(() => communicator.ReceivePacket(out packet));
            }
        }
        // fails for npcap because handling the buffer differently
        [Fact]
        public void SetSmallKernelBufferSizeGetSomePacketsErrorTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);
                communicator.SetKernelBufferSize(10);
                Packet packet = _random.NextEthernetPacket(100, SourceMac, DestinationMac);
                communicator.SendPacket(packet);
                int numPacketsGot;
                Assert.Throws<InvalidOperationException>(() => communicator.ReceiveSomePackets(out numPacketsGot, 1, delegate { }));
            }
        }
        // fails for npcap because handling the buffer differently
        [Fact]
        public void SetSmallKernelBufferSizeGetPacketsErrorTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);
                communicator.SetKernelBufferSize(10);
                Packet packet = _random.NextEthernetPacket(100, SourceMac, DestinationMac);
                communicator.SendPacket(packet);

                Assert.Throws<InvalidOperationException>(() => communicator.ReceivePackets(1, delegate { }));
            }
        }
        // fails for npcap because handling the buffer differently
        [Fact]
        public void SetSmallKernelBufferSizeGetNextStatisticsErrorTest()
        {
#if !REAL
            _pal.SetWinPcapBehavior();
#endif
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.Mode = PacketCommunicatorMode.Statistics;
                communicator.SetKernelBufferSize(10);
                PacketSampleStatistics statistics;
                Assert.Throws<InvalidOperationException>(() => communicator.ReceiveStatistics(out statistics));
            }
        }
        // fails for npcap because handling the buffer differently
        [Fact]
        public void SetSmallKernelBufferSizeGetStatisticsErrorTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.Mode = PacketCommunicatorMode.Statistics;
                communicator.SetKernelBufferSize(10);
                Assert.Throws<InvalidOperationException>(() => communicator.ReceiveStatistics(1, delegate { Assert.False(true); }));
            }
        }

        [Fact]
        public void SetNonBlockTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.False(communicator.NonBlocking);
                communicator.NonBlocking = false;
                Assert.False(communicator.NonBlocking);
                communicator.NonBlocking = true;
                Assert.True(communicator.NonBlocking);
            }
        }
        // fails on REAL unix because no packets are sent and sampling not supported
        [Fact]
        public void SetBigKernelMinimumBytesToCopyTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);
                communicator.SetKernelMinimumBytesToCopy(1024 * 1024);
                Packet expectedPacket = _random.NextEthernetPacket(100, SourceMac, DestinationMac);
                for (int i = 0; i != 5; ++i)
                {
                    communicator.SendPacket(expectedPacket);
                    Packet packet;
                    DateTime start = DateTime.Now;
                    PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                    DateTime end = DateTime.Now;
                    Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                    Assert.Equal(expectedPacket, packet);
                    MoreAssert.IsBigger(TimeSpan.FromSeconds(0.9), end - start);
                }
            }
        }
        // fails on REAL unix because no packets are sent and fails in simulation ReceivePacket does not wait for read timeout
        [Fact]
        public void SetSmallKernelMinimumBytesToCopyTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);
                communicator.SetKernelMinimumBytesToCopy(1);
                Packet expectedPacket = _random.NextEthernetPacket(100, SourceMac, DestinationMac);
                for (int i = 0; i != 100; ++i)
                {
                    communicator.SendPacket(expectedPacket);
                    Packet packet;
                    DateTime start = DateTime.Now;
                    PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                    DateTime end = DateTime.Now;
                    Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                    Assert.Equal(expectedPacket, packet);
                    MoreAssert.IsSmallerOrEqual(TimeSpan.FromSeconds(0.07), end - start);
                }
            }
        }
        // fails on REAL unix because no packets are sent
        [Fact]
        public void SetSamplingMethodOneEveryNTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);
                communicator.SetSamplingMethod(new SamplingMethodOneEveryCount(5));
                for (int i = 0; i != 20; ++i)
                {
                    Packet expectedPacket = _random.NextEthernetPacket(60 * (i + 1), SourceMac, DestinationMac);
                    communicator.SendPacket(expectedPacket);
                }

                Packet packet;
                PacketCommunicatorReceiveResult result;
                for (int i = 0; i != 4; ++i)
                {
                    result = communicator.ReceivePacket(out packet);
                    Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                    Assert.Equal(60 * 5 * (i + 1), packet.Length);
                }
                result = communicator.ReceivePacket(out packet);
                Assert.Equal(PacketCommunicatorReceiveResult.Timeout, result);
                Assert.Null(packet);
            }
        }
        // fails on REAL unix because no packets are sent and sampling not supported
        [Fact]
        public void SetSamplingMethodFirstAfterIntervalTest()
        {
            Random random = new Random();

            MacAddress sourceMac = random.NextMacAddress();
            MacAddress destinationMac = random.NextMacAddress();

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + sourceMac + " and ether dst " + destinationMac);
                communicator.SetSamplingMethod(new SamplingMethodFirstAfterInterval(TimeSpan.FromSeconds(1)));
                int numPacketsGot;
                communicator.ReceiveSomePackets(out numPacketsGot, 100, p => { });

                Packet[] packetsToSend = new Packet[11];
                packetsToSend[0] = _random.NextEthernetPacket(60, sourceMac, destinationMac);
                for (int i = 0; i != 10; ++i)
                    packetsToSend[i + 1] = _random.NextEthernetPacket(60 * (i + 2), sourceMac, destinationMac);

                List<Packet> packets = new List<Packet>(6);
                var task = Task.Factory.StartNew(() => packets.AddRange(communicator.ReceivePackets(6)));

                communicator.SendPacket(packetsToSend[0]);
                TaskExtensions.Delay(TimeSpan.FromSeconds(0.7)).Wait();
                for (int i = 0; i != 10; ++i)
                {
                    communicator.SendPacket(packetsToSend[i + 1]);
                    TaskExtensions.Delay(TimeSpan.FromSeconds(0.55)).Wait();
                }
                var delay = TaskExtensions.Delay(TimeSpan.FromSeconds(2));
                Task.WaitAny(task, delay);

                Assert.True(6 == packets.Count, packets.Select(p => (p.Timestamp - packets[0].Timestamp).TotalSeconds + "(" + p.Length + ")").SequenceToString(", "));
                Packet packet = null;
                for (int i = 0; i != 6; ++i)
                {
                    Assert.True(60 * (i * 2 + 1) == packets[i].Length, i.ToString());
                }
                PacketCommunicatorReceiveResult result = PacketCommunicatorReceiveResult.None;
                task = Task.Factory.StartNew(() => result = communicator.ReceivePacket(out packet));

                delay = TaskExtensions.Delay(TimeSpan.FromSeconds(2));
                Task.WaitAny(task, delay);

                Assert.Equal(PacketCommunicatorReceiveResult.Timeout, result);
                Assert.Null(packet);
            }
        }

        [Fact]
        public void SetSamplingMethodOneEveryNErrorTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => communicator.SetSamplingMethod(new SamplingMethodOneEveryCount(0)));
            }
        }

        [Fact]
        public void SetSamplingMethodFirstAfterIntervalNegativeMsErrorTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => communicator.SetSamplingMethod(new SamplingMethodFirstAfterInterval(-1)));
            }
        }

        [Fact]
        public void SetSamplingMethodFirstAfterIntervalNegativeTimespanErrorTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => communicator.SetSamplingMethod(new SamplingMethodFirstAfterInterval(TimeSpan.FromSeconds(-1))));
            }
        }

        [Fact]
        public void SetSamplingMethodFirstAfterIntervalBigTimespanErrorTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => communicator.SetSamplingMethod(new SamplingMethodFirstAfterInterval(TimeSpan.FromDays(25))));
            }
        }

        [Fact]
        public void SetInvalidDataLink()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.Throws<InvalidOperationException>(() => communicator.DataLink = new PcapDataLink(0));
            }
        }
        // fails on REAL unix because sampling not supported
        [Fact]
        public void SendZeroPacket()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SendPacket(new Packet(new byte[0], DateTime.Now, DataLinkKind.Ethernet));
            }
        }

        [Fact]
        public void Npcap_Loopback_CorrectException()
        {
            var device = LivePacketDevice.AllLocalMachine.First(x => (x.Attributes & DeviceAttributes.Loopback) != 0);
            Assert.Throws<InvalidOperationException>(device.GetPnpDeviceId);
        }

        [Fact]
        public void Winpcap_Loopback_CorrectException()
        {
#if !REAL
            _pal.SetWinPcapBehavior();
#endif
            Assert.Empty(LivePacketDevice.AllLocalMachine.Where(x => (x.Attributes & DeviceAttributes.Loopback) != 0));
        }

        public static PacketCommunicator OpenLiveDevice(int snapshotLength)
        {
#if REAL
            const string ForcedName = ""; // type here adapter name if first is not appropriated
            NetworkInterface networkInterface =
                NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(
                    ni => !ni.IsReceiveOnly && ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet && ni.OperationalStatus == OperationalStatus.Up &&
                          (string.IsNullOrEmpty(ForcedName) || ForcedName == ni.Name));
            LivePacketDevice device = networkInterface.GetLivePacketDevice();
            MoreAssert.IsMatch(@"Network adapter '.*' on local host", device.Description);
            Assert.Equal(DeviceAttributes.None, device.Attributes);
            Assert.NotEqual(MacAddress.Zero, device.GetMacAddress());
            if (Environment.OSVersion.Platform != PlatformID.Unix && Environment.OSVersion.Platform != PlatformID.MacOSX)
                Assert.NotEqual(string.Empty, device.GetPnpDeviceId());
            MoreAssert.IsBiggerOrEqual(1, device.Addresses.Count);
            foreach (DeviceAddress address in device.Addresses)
            {
                if (address.Address.Family == SocketAddressFamily.Internet)
                {
                    MoreAssert.IsMatch("Address: " + SocketAddressFamily.Internet + @" [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ " +
                                       "Netmask: " + SocketAddressFamily.Internet + @" 255\.[0-9]+\.[0-9]+\.[0-9]+ " +
                                       "Broadcast: " + SocketAddressFamily.Internet + @" [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",
                                       address.ToString());
                }
                else
                {
                    Assert.Equal(SocketAddressFamily.Internet6, address.Address.Family);
                    var match = "Address: " + SocketAddressFamily.Internet6 + @" (?:[0-9A-F]{4}:){7}[0-9A-F]{4}" +
                                " Netmask: " + SocketAddressFamily.Internet6 + @" (?:[0-9A-F]{4}:){7}[0-9A-F]{4}";
                    if (Environment.OSVersion.Platform != PlatformID.Unix && Environment.OSVersion.Platform != PlatformID.MacOSX)
                        match += " Broadcast: " + SocketAddressFamily.Internet6 + @" (?:[0-9A-F]{4}:){7}[0-9A-F]{4}";
                    MoreAssert.IsMatch(match, address.ToString());
                }
            }

            PacketCommunicator communicator = device.Open(snapshotLength, PacketDeviceOpenAttributes.Promiscuous, 1000);
            try
            {
                MoreAssert.AreSequenceEqual(new[] {DataLinkKind.Ethernet, DataLinkKind.Docsis}.Select(kind => new PcapDataLink(kind)), communicator.SupportedDataLinks);
                PacketTotalStatistics totalStatistics = communicator.TotalStatistics;
                Assert.Equal<object>(totalStatistics, totalStatistics);
                Assert.NotNull(totalStatistics);
                Assert.Equal(totalStatistics.GetHashCode(), totalStatistics.GetHashCode());
                Assert.True(totalStatistics.Equals(totalStatistics));
                Assert.False(totalStatistics.Equals(null));
                Assert.NotNull(totalStatistics);
                MoreAssert.IsSmallerOrEqual<uint>(1, totalStatistics.PacketsCaptured, "PacketsCaptured"); // fails randomly, dependent on traffic
                Assert.Equal<uint>(0, totalStatistics.PacketsDroppedByDriver);
                if (Environment.OSVersion.Platform != PlatformID.Unix && Environment.OSVersion.Platform != PlatformID.MacOSX)
                    Assert.Equal<uint>(0, totalStatistics.PacketsDroppedByInterface);
                MoreAssert.IsSmallerOrEqual<uint>(1, totalStatistics.PacketsReceived);
                Assert.NotNull(totalStatistics.ToString());
                if (Environment.OSVersion.Platform != PlatformID.Unix && Environment.OSVersion.Platform != PlatformID.MacOSX)
                    communicator.SetKernelBufferSize(2 * 1024 * 1024); // 2 MB instead of 1
                communicator.SetKernelMinimumBytesToCopy(10); // 10 bytes minimum to copy
                if (Environment.OSVersion.Platform != PlatformID.Unix && Environment.OSVersion.Platform != PlatformID.MacOSX)
                    communicator.SetSamplingMethod(new SamplingMethodNone());
                Assert.Equal(DataLinkKind.Ethernet, communicator.DataLink.Kind);
                communicator.DataLink = communicator.DataLink;
                Assert.Equal("EN10MB (Ethernet)", communicator.DataLink.ToString());
                Assert.Equal(communicator.DataLink, new PcapDataLink(communicator.DataLink.Name));
                Assert.True(communicator.IsFileSystemByteOrder);
                Assert.Equal(PacketCommunicatorMode.Capture, communicator.Mode);
                Assert.False(communicator.NonBlocking);
                Assert.Equal(snapshotLength, communicator.SnapshotLength);
                return communicator;
            }
            catch (Exception)
            {
                communicator.Dispose();
                throw;
            }
#else
            return new TestablePacketCommunicator(snapshotLength, PacketDeviceOpenAttributes.Promiscuous, 1000);
#endif
        }

        public static PacketCommunicator OpenLiveDevice()
        {
            return OpenLiveDevice(PacketDevice.DefaultSnapshotLength);
        }

        private static readonly Random _random = new Random();
    }
}
