using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using PcapDotNet.Packets.TestUtils;
using Xunit;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for PacketTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class PacketTests
    {
        [Fact]
        public void RandomPacketTest()
        {
            int seed = new Random().Next();
            Console.WriteLine("Seed: " + seed);
            Random random = new Random(seed);

            for (int i = 0; i != 1000; ++i)
            {
                Packet packet = random.NextPacket(random.Next(10 * 1024));

                // Check Equals
                Assert.Equal(packet, new Packet(packet.Buffer, packet.Timestamp.AddHours(1), packet.DataLink));
                Assert.NotEqual(packet, random.NextPacket(random.Next(10 * 1024)));
                if (packet.Length != 0)
                    Assert.NotEqual(packet, random.NextPacket(packet.Length));

                // Check GetHashCode
                Assert.Equal(packet.GetHashCode(), new Packet(packet.Buffer, packet.Timestamp.AddHours(1), packet.DataLink).GetHashCode());
                Assert.NotEqual(packet.GetHashCode(), random.NextPacket(random.Next(10 * 1024)).GetHashCode());
                if (packet.Length != 0)
                    Assert.NotEqual(packet.GetHashCode(), random.NextPacket(packet.Length).GetHashCode());

                // Check ToString
                Assert.NotNull(packet.ToString());

                Assert.False(new Packet(packet.Buffer, DateTime.Now, (DataLinkKind)((int)DataLinkKind.Ethernet + 1)).IsValid);

                // Check Enumerable
                IEnumerable enumerable = packet;
                int offset = 0;
                foreach (byte b in enumerable)
                    Assert.Equal(packet[offset++], b);

            }
        }

        [Fact]
        public void PacketConstructorNullDataTest()
        {
            Assert.Throws<ArgumentNullException>(() => new Packet(null, DateTime.Now, DataLinkKind.Ethernet));
        }

        [Fact]
        public void PacketIListTest()
        {
            byte[] buffer = new byte[]{1,2,3,4,5};
            IList<byte> packet = new Packet(buffer, DateTime.Now, DataLinkKind.Ethernet);

            Assert.True(packet.Contains(1));

            buffer = new byte[buffer.Length];
            packet.CopyTo(buffer, 0);
            packet.SequenceEqual(buffer);

            Assert.Equal(1, packet.IndexOf(2));
            Assert.Equal(buffer.Length, packet.Count);
            Assert.Equal(buffer[2], packet[2]);
            Assert.True(packet.IsReadOnly);
        }

        [Fact]
        public void MutationMethodsTest()
        {
            string[] methodNames = new[] {"Add", "Clear", "Insert", "Remove", "RemoveAt", "set_Item"};

            Packet packet = new Random().NextPacket(100);
            var methods = from method in typeof(Packet).GetMethods()
                          where (methodNames.Contains(method.Name))
                          select method;

            Assert.Equal(methodNames.Length, methods.Count());

            foreach (var method in methods)
            {
                var parameters = from parameter in method.GetParameters()
                                 select Activator.CreateInstance(parameter.ParameterType);
                try
                {
                    method.Invoke(packet, parameters.ToArray());
                }
                catch (TargetInvocationException e)
                {
                    Assert.IsType<InvalidOperationException>(e.InnerException);
                    continue;
                }

                Assert.False(true);
            }
        }

        [Fact]
        public void PacketFromHexadecimalStringNullTest()
        {
            Assert.Throws<ArgumentNullException>(() => Packet.FromHexadecimalString(null, DateTime.MinValue, DataLinkKind.Ethernet));
        }
    }
}
