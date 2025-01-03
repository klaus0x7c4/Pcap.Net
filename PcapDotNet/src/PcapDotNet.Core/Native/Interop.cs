// This file is inspired by SharpPcap project
using System;

namespace PcapDotNet.Core.Native
{
    public static class Interop
    {
        static Interop()
        {
            if (Environment.OSVersion.Platform != PlatformID.MacOSX
                && Environment.OSVersion.Platform != PlatformID.Unix)
            {
                Pcap = new PcapWindowsPal();
                Sys = new SysWindowsPal();
            }
            else
            {
                Pcap = new PcapUnixPal();
                Sys = new SysUnixPal();
            }
        }

        // ToDo: remove if switched to .netstandard 2.1 or higher
        public static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static IPcapPal Pcap { get; private set; }

        internal static ISysPal Sys { get; private set; }
    }
}
