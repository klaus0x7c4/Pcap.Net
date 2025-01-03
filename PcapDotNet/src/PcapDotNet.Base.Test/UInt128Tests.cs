using System;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Numerics;
using PcapDotNet.TestUtils;
using Xunit;

namespace PcapDotNet.Base.Test
{
    /// <summary>
    /// Summary description for UInt128Tests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class UInt128Tests
    {
        [Fact]
        public void UInt128Test()
        {
            Random random = new Random();
            for (int i = 0; i != 1000; ++i)
            {
                UInt128 value = random.NextUInt128();

                // Test comparisons.
                Assert.Equal(value, value);
                Assert.NotEqual(value.ToString(), string.Empty);
                Assert.NotEqual(value, UInt128.MaxValue);
                Assert.NotEqual(value, UInt128.Zero);
                // ReSharper disable EqualExpressionComparison
                Assert.True(value == value);
                Assert.False(value != value);
                Assert.True(value <= value);
                Assert.True(value >= value);
                // ReSharper restore EqualExpressionComparison
                if (value != UInt128.MaxValue)
                {
                    Assert.True(value < value + 1);
                    Assert.True(value <= value + 1);
                    Assert.True(value + 1 > value);
                    Assert.True(value + 1 >= value);
                }

                // Test Parse()
                Assert.Equal(value, UInt128.Parse(value.ToString()));
                Assert.Equal(value, UInt128.Parse(value.ToString(), CultureInfo.InvariantCulture));
                Assert.Equal(value, UInt128.Parse(value.ToString(), NumberStyles.Integer));

                // Test TryParse()
                UInt128 actualValue;
                Assert.True(UInt128.TryParse(value.ToString(), out actualValue));
                Assert.Equal(value, actualValue);
                Assert.True(UInt128.TryParse(value.ToString(CultureInfo.InvariantCulture), out actualValue));
                Assert.Equal(value, actualValue);

                // Cast to UInt64
                ulong smallValue = random.NextULong();
                Assert.Equal(smallValue, (ulong)((UInt128)smallValue));
            }
        }

        [Fact]
        public void CastToULongOverflow()
        {
            Random random = new Random();
            UInt128 value;
            ulong overflow = random.NextULong(ulong.MaxValue);
            try
            {
                value = (UInt128)(((BigInteger)ulong.MaxValue) + overflow + 1);
            }
            catch (Exception)
            {
                Assert.False(true);
                return;
            }
            Assert.Equal(overflow, (ulong)value); 
        }

        [Fact]
        public void ParseOverflow()
        {
            Assert.Throws<OverflowException>(() => UInt128.Parse("-1"));
        }

        [Fact]
        public void TryParseOverflow()
        {
            UInt128 actual;
            Assert.False(UInt128.TryParse("-1", out actual));
            Assert.Equal(UInt128.Zero, actual);
            Assert.False(UInt128.TryParse((UInt128.MaxValue + BigInteger.One).ToString(), out actual));
            Assert.Equal(UInt128.Zero, actual);
        }

        [Fact]
        public void ShiftRightTest()
        {
            const string ValueString = "0123456789ABCDEFFEDCBA9876543210";
            UInt128 value = UInt128.Parse(ValueString, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            Assert.Equal(UInt128.Parse(ValueString, NumberStyles.HexNumber, CultureInfo.InvariantCulture), value);

            for (int i = 0; i <= 124; i += 4)
            {
                string expectedValueString = new string('0', i / 4) + ValueString.Substring(0, ValueString.Length - i / 4);
                UInt128 expectedValue = UInt128.Parse(expectedValueString, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                Assert.Equal(expectedValue, value >> i);
                Assert.Equal(expectedValue, value >> (i / 2) >> (i / 2));
                Assert.Equal(expectedValue, value >> (i / 4) >> (i / 4) >> (i / 4) >> (i / 4));
            }

            Assert.Equal<UInt128>(value >> 128, 0);
        }

        [Fact]
        public void SumTest()
        {
            UInt128 value1 = 0;
            UInt128 value2 = 0;
            Assert.Equal<UInt128>(0, value1 + value2);

            value1 = 1;
            Assert.Equal<UInt128>(1, value1 + value2);
            
            value2 = 1;
            Assert.Equal<UInt128>(2, value1 + value2);

            value1 = 100;
            Assert.Equal<UInt128>(101, value1 + value2);

            value2 = 1000;
            Assert.Equal<UInt128>(1100, value1 + value2);

            value1 = ulong.MaxValue;
            value2 = 0;
            Assert.Equal(ulong.MaxValue, value1 + value2);

            value2 = 1;
            Assert.Equal(new UInt128(1,0), value1 + value2);

            value2 = 2;
            Assert.Equal(new UInt128(1, 1), value1 + value2);

            value2 = ulong.MaxValue;
            Assert.Equal(new UInt128(1, ulong.MaxValue - 1), value1 + value2);

            value1 = 2;
            value2 = new UInt128(1000, ulong.MaxValue);
            Assert.Equal(new UInt128(1001, 1), value1 + value2);

            value1 = new UInt128(100, ulong.MaxValue / 2 + 1);
            value2 = new UInt128(1000, ulong.MaxValue / 2 + 2);
            Assert.Equal(new UInt128(1101, 1), value1 + value2);

            value1 = new UInt128(ulong.MaxValue / 2, ulong.MaxValue / 2 + 1);
            value2 = new UInt128(ulong.MaxValue / 2, ulong.MaxValue / 2 + 2);
            Assert.Equal(new UInt128(ulong.MaxValue, 1), value1 + value2);

            value1 = new UInt128(ulong.MaxValue / 2 + 1, ulong.MaxValue / 2 + 1);
            value2 = new UInt128(ulong.MaxValue / 2, ulong.MaxValue / 2 + 2);
            Assert.Equal(new UInt128(0, 1), value1 + value2);
        }

        [Fact]
        public void Substract()
        {
            UInt128 value1 = 0;
            UInt128 value2 = 0;
            Assert.Equal<UInt128>(0, value1 - value2);

            value1 = 1;
            Assert.Equal<UInt128>(1, value1 - value2);

            value2 = 1;
            Assert.Equal<UInt128>(0, value1 - value2);

            value1 = 100;
            Assert.Equal<UInt128>(99, value1 - value2);

            value1 = new UInt128(1, 0);
            value2 = 0;
            Assert.Equal<UInt128>(value1, value1 - value2);

            value2 = 1;
            Assert.Equal<UInt128>(ulong.MaxValue, value1 - value2);

            value2 = 2;
            Assert.Equal<UInt128>(ulong.MaxValue - 1, value1 - value2);

            value1 = new UInt128(100, 1);
            Assert.Equal<UInt128>(new UInt128(99, ulong.MaxValue), value1 - value2);

            value1 = 1;
            Assert.Equal<UInt128>(UInt128.MaxValue, value1 - value2);
        }

        [Fact]
        public void BitwiseAndTest()
        {
            const string ValueString = "0123456789ABCDEFFEDCBA9876543210";
            UInt128 value = UInt128.Parse(ValueString, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            Assert.Equal(UInt128.Parse(ValueString, NumberStyles.HexNumber, CultureInfo.InvariantCulture), value);

            for (int i = 0; i <= 32; ++i)
            {
                string andValueString = new string('0', i) + new string('F', ValueString.Length - i);
                UInt128 andValue = UInt128.Parse("0" + andValueString, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                string expectedValueString = new string('0', i) + ValueString.Substring(i, ValueString.Length - i);
                UInt128 expectedValue = UInt128.Parse(expectedValueString, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                UInt128 actualValue = value & andValue;
                Assert.Equal(expectedValue, actualValue);
            }
        }

        [Fact]
        public void BitwiseOrTest()
        {
            const string ValueString = "0123456789ABCDEFFEDCBA9876543210";
            UInt128 value = UInt128.Parse(ValueString, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            Assert.Equal(UInt128.Parse(ValueString, NumberStyles.HexNumber, CultureInfo.InvariantCulture), value);

            for (int i = 0; i <= 32; ++i)
            {
                string orValueString = new string('0', i) + new string('F', ValueString.Length - i);
                UInt128 orValue = UInt128.Parse("0" + orValueString, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                string expectedValueString = ValueString.Substring(0, i) + new string('F', ValueString.Length - i);
                UInt128 expectedValue = UInt128.Parse(expectedValueString, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                UInt128 actualValue = value | orValue;
                Assert.Equal(expectedValue, actualValue);
            }
        }

        [Fact]
        public void ParseNullTest()
        {
            Assert.Throws<ArgumentNullException>(() => UInt128.Parse(null, NumberStyles.HexNumber, CultureInfo.InvariantCulture));
        }

        [Fact]
        public void ToStringTest()
        {
            const string ValueString = "1234567890abcdeffedcba0987654321";
            UInt128 value = UInt128.Parse(ValueString, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            Assert.Equal(ValueString, value.ToString("x32"));
        }

        [Fact]
        public void ToStringTestFirstBitIsOne()
        {
            const string ValueString = "fedcba9876543210fedcba9876543210";
            UInt128 value = UInt128.Parse(ValueString, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            Assert.Equal(ValueString, value.ToString("x32"));
        }
    }
}
