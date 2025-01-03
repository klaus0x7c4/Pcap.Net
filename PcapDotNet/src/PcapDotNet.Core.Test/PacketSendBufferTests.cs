using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using PcapDotNet.Packets;
using PcapDotNet.Packets.TestUtils;
using PcapDotNet.TestUtils;
using Xunit;

namespace PcapDotNet.Core.Test
{
    /// <summary>
    /// Summary description for PacketSendQueueTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class PacketSendQueueTests
    {
#if !REAL
        public PacketSendQueueTests()
        {
            TestablePcapPal.UseTestPal();
        }
#endif

        // fails on REAL unix because no packets are sent
        [Fact]
        public void TransmitQueueToLiveTest()
        {
            TestTransmitQueueToLive(0, 100, 0.5, false);
            TestTransmitQueueToLive(10, 60, 0.5, false);
            TestTransmitQueueToLive(10, 600, 0.5, false);
            TestTransmitQueueToLive(10, 1500, 0.5, false);
            TestTransmitQueueToLive(10, 60, 0.5, true);
        }
#if REAL // only testable on real OfflinePacketCommunicator
        // fails on REAL unix because no packets are sent
        [Fact]
        public void TransmitQueueToOfflineTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            List<Packet> packetsToSend;
            using (PacketSendBuffer queue = BuildQueue(out packetsToSend, 100, 100, SourceMac, DestinationMac, 0.5))
            {
                using (PacketCommunicator communicator = OfflinePacketDeviceTests.OpenOfflineDevice())
                {
                    communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);
                    Assert.Throws<InvalidOperationException>(() => communicator.Transmit(queue, false));
                }
            }
        }
#endif
        [Fact]
        public void EnqueueNullTest()
        {
            using (PacketSendBuffer queue = new PacketSendBuffer(10))
            {
                Assert.Throws<ArgumentNullException>(() => queue.Enqueue(null));
            }
        }

        // this test is only testing the TestablePacketCommunicator, except REAL is set
#if REAL
        [Fact]
        public void TransmitNullTest()
        {
            using (PacketCommunicator communicator = LivePacketDeviceTests.OpenLiveDevice())
            {
                Assert.Throws<ArgumentNullException>(() => communicator.Transmit(null, false));
            }
        }
#endif
        // fails on linux because of not supported pcap_sendqueue_transmit
        // since Npcap 0.999 and REAL set: on windows systems with intel network adapter will fail
        private static void TestTransmitQueueToLive(int numPacketsToSend, int packetSize, double secondsBetweenTimestamps, bool isSynced)
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            List<Packet> packetsToSend;
            using (PacketSendBuffer queue = BuildQueue(out packetsToSend, numPacketsToSend, packetSize, SourceMac, DestinationMac, secondsBetweenTimestamps))
            {
                using (PacketCommunicator communicator = LivePacketDeviceTests.OpenLiveDevice())
                {
                    communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);
                    communicator.Transmit(queue, isSynced);

                    DateTime lastTimestamp = DateTime.MinValue;
                    int numPacketsHandled = 0;
                    int numPacketsGot;
                    PacketCommunicatorReceiveResult result =
                        communicator.ReceiveSomePackets(out numPacketsGot, numPacketsToSend,
                                                    delegate(Packet packet)
                                                        {
                                                            Assert.Equal(packetsToSend[numPacketsHandled], packet);
                                                            if (numPacketsHandled > 0)
                                                            {
                                                                TimeSpan expectedDiff;
                                                                if (isSynced)
                                                                {
                                                                    expectedDiff =
                                                                        packetsToSend[numPacketsHandled].Timestamp -
                                                                        packetsToSend[numPacketsHandled - 1].Timestamp;
                                                                }
                                                                else
                                                                {
                                                                    expectedDiff = TimeSpan.Zero;
                                                                }
                                                                TimeSpan actualDiff = packet.Timestamp - lastTimestamp;
                                                                MoreAssert.IsInRange(
                                                                    expectedDiff.Subtract(TimeSpan.FromSeconds(0.06)),
                                                                    expectedDiff.Add(TimeSpan.FromSeconds(0.1)),
                                                                    actualDiff, "actualDiff");
                                                            }
                                                            lastTimestamp = packet.Timestamp;
                                                            ++numPacketsHandled;
                                                        });

                    Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                    Assert.True(numPacketsToSend == numPacketsGot, "numPacketsGot");
                    Assert.True(numPacketsToSend == numPacketsHandled, "numPacketsHandled");
                }
            }
        }

        private static PacketSendBuffer BuildQueue(out List<Packet> packetsToSend, int numPackets, int packetSize, string sourceMac, string destinationMac, double secondsBetweenTimestamps)
        {
            int rawPacketSize = packetSize + Native.Interop.Pcap.PcapHeaderSize;
            PacketSendBuffer queue = new PacketSendBuffer((uint)(numPackets * rawPacketSize));
            try
            {
                DateTime timestamp = DateTime.Now.AddSeconds(-100);
                packetsToSend = new List<Packet>(numPackets);
                for (int i = 0; i != numPackets; ++i)
                {
                    Packet packetToSend = _random.NextEthernetPacket(packetSize, timestamp, sourceMac, destinationMac);
                    queue.Enqueue(packetToSend);
                    packetsToSend.Add(packetToSend);
                    timestamp = timestamp.AddSeconds(secondsBetweenTimestamps);
                }
            }
            catch (Exception)
            {
                queue.Dispose();
                throw;
            }

            return queue;
        }

        private static readonly Random _random = new Random();
    }
}
