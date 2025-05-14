using System;
using System.Linq;
using Xunit;

namespace PcapDotNet.Base.Test
{
    public class StringExtensionsTests
    {
        [Theory]
        [InlineData("abc", 'a', 'z', true)]
        [InlineData("abc.pcap", (char)0, (char)255, true)]
        [InlineData("foo_bar.pcap", (char)0, (char)255, true)]
        [InlineData("föö_bar.pcap", (char)0, (char)255, true)]
        [InlineData("straße.pcap", (char)0, (char)255, true)]
        [InlineData("דמפ.pcap", (char)0, (char)255, false)]
        [InlineData("aBc", 'a', 'z', false)]
        public void AreAllCharactersInRangeTest(string value, char minValue, char maxValue, bool expectedResult)
        {
            bool result = value.AreAllCharactersInRange(minValue, maxValue);
            Assert.Equal(expectedResult, result);
        }

        [Fact]
        public void AreAllCharactersInRangeNullTest()
        {
            Assert.Throws<ArgumentNullException>(() => StringExtensions.AreAllCharactersInRange(null,'a', 'z'));
        }

        [Fact]
        public void AreAllCharactersInRangeWithNonePrintableCharactersTrue()
        {
            var foo = new string(Enumerable.Range(0, 256).Select(x => (char)x).ToArray());
            bool result = foo.AreAllCharactersInRange((char)0, (char)255);
            Assert.True(result);
        }

        [Fact]
        public void AreAllCharactersInRangeWithNonePrintableCharactersFalse()
        {
            var foo = new string(Enumerable.Range(0, 257).Select(x => (char)x).ToArray());
            bool result = foo.AreAllCharactersInRange((char)0, (char)255);
            Assert.False(result);
        }
    }
}
