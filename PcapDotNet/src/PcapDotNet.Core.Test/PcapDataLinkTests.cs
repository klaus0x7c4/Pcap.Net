using System;
using System.Diagnostics.CodeAnalysis;
using PcapDotNet.Packets;
using Xunit;

namespace PcapDotNet.Core.Test
{
    /// <summary>
    /// Summary description for PcapDataLinkTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class PcapDataLinkTests
    {
#if !REAL
        public PcapDataLinkTests()
        {
            TestablePcapPal.UseTestPal();
        }
#endif

        [Fact]
        public void TestValidDataLinks()
        {
            PcapDataLink dataLink = new PcapDataLink();
            Assert.Equal(new PcapDataLink("NULL"), dataLink);
            string previousDataLinkName = null;
            for (int i = 0; i < 300; ++i)
            {
                dataLink = new PcapDataLink(i);
                string dataLinkName;
                try
                {
                    dataLinkName = dataLink.Name;
                }
                catch (InvalidOperationException)
                {
                    // Ignore invalid values
                    continue;
                }

                Assert.Equal(new PcapDataLink(dataLinkName), dataLink);
                Assert.False(dataLink.Equals(null));
                Assert.True(new PcapDataLink(dataLinkName) == dataLink);
                Assert.False(new PcapDataLink(dataLinkName) != dataLink);
                Assert.True(previousDataLinkName == null || new PcapDataLink(previousDataLinkName) != dataLink);
                Assert.NotNull(dataLink.Description);
                Assert.Equal(i, dataLink.Value);
                Assert.Equal(dataLink.Value.GetHashCode(), dataLink.GetHashCode());

                previousDataLinkName = dataLinkName;
            }
        }

        [Fact]
        public void ValidKindsTest()
        {
            foreach (DataLinkKind kind in typeof(DataLinkKind).GetEnumValues())
            {
                Assert.Equal(kind, new PcapDataLink(kind).Kind);
            }
        }

        [Fact]
        public void UnsupportedKindErrorTest()
        {
            PcapDataLink dataLink = new PcapDataLink();
            Assert.Throws<NotSupportedException>(() => dataLink.Kind);
        }

        [Fact]
        public void NoDescriptionErrorTest()
        {
            PcapDataLink dataLink = GetInvalidDataLink();
            Assert.Throws<InvalidOperationException>(() => dataLink.Description);
        }

        [Fact]
        public void InvalidNameErrorTest()
        {
            Assert.Throws<ArgumentException>(() => new PcapDataLink("Invalid Name"));
        }

        [Fact]
        public void InvalidKindTest()
        {
            const DataLinkKind InvalidKind = (DataLinkKind)100;
            Assert.Throws<NotSupportedException>(() => new PcapDataLink(InvalidKind));
        }

        private static PcapDataLink GetInvalidDataLink()
        {
            for (int i = 0; i < 300; ++i)
            {
                PcapDataLink dataLink = new PcapDataLink(i);
                try
                {
                    string dataLinkName = dataLink.Name;
                    Assert.NotNull(dataLinkName);
                }
                catch (InvalidOperationException)
                {
                    return dataLink;
                }
                catch (Exception)
                {
                    Assert.False(true);
                }
            }
            Assert.False(true);
            return new PcapDataLink();
        }
    }
}
