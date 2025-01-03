using System.Diagnostics.CodeAnalysis;
using PcapDotNet.TestUtils;
using Xunit;

namespace PcapDotNet.Core.Test
{
#if REAL
    /// <summary>
    /// Summary description for PcapLibTests.
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class PcapLibTests
    {
        [Fact]
        public void VersionTest()
        {
            const string VersionNumberRegex = @"[0-9]+\.[0-9]+(?:\.| beta)[0-9]+(?:\.[0-9]+)?";
            const string LibpcapVersionRegex = @"((?:[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:-PRE-GIT_\d{4}_\d\d_\d\d)?( \(with[ \w]*\)?)?|(?:[0-9]\.[0-9] branch [0-9]_[0-9]_rel0b \([0-9]+\)))"; // surround with brackets that $ counts!
            var possibleVersions = new [] {
                "WinPcap version 4.1.1 (packet.dll version 4.1.0.1753), based on libpcap version 1.0 branch 1_0_rel0b (20091008)",
                "WinPcap version 4.1 beta5 (packet.dll version 4.1.0.1452), based on libpcap version 1.0.0",
                "Npcap version 1.79, based on libpcap version 1.10.4",
                "libpcap version 1.10.5 (with TPACKET_V2)",
                "libpcap version 1.10.5 (with TPACKET_V3)",
                "libpcap version 1.9.0-PRE-GIT_2017_07_30 (with TPA", // compiled from e31793ccad591
                PcapLibrary.Version
            };

            string versionRegex = "(^WinPcap version " + VersionNumberRegex + @" \(packet\.dll version " + VersionNumberRegex + @"\), based on libpcap version " + LibpcapVersionRegex + "$)";
            versionRegex += $@"|(^Npcap version [0-9]+\.[0-9]+(?:\.[0-9]+)?, based on libpcap version {LibpcapVersionRegex}$)";
            versionRegex += $@"|(^libpcap version {LibpcapVersionRegex}$)";
            foreach (var version in possibleVersions)
            {
                MoreAssert.IsMatch(versionRegex, version);
            }
        }
    }
#endif
}
