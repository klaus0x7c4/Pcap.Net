namespace PcapDotNet.Core
{
    /// <summary>
    /// Constants and static helper methods
    /// </summary>
    public class Pcap
    {
        internal const int MAX_PACKET_SIZE = 65536;

        internal const int PCAP_ERRBUF_SIZE = 256;

        internal const string PCAP_SRC_IF_STRING = "rpcap://";

        #region native error codes
        /*
         * Error codes for the pcap API.
         * These will all be negative, so you can check for the success or
         * failure of a call that returns these codes by checking for a
         * negative value.
         */
        /// <summary>generic error code</summary>
        internal const int PCAP_ERROR = -1;
        /// <summary>loop terminated by pcap_breakloop</summary>
        internal const int PCAP_ERROR_BREAK = -2;
        /// <summary>the capture needs to be activated</summary>
        internal const int PCAP_ERROR_NOT_ACTIVATED = -3;
        /// <summary>the operation can't be performed on already activated captures</summary>
        internal const int PCAP_ERROR_ACTIVATED = -4;
        /// <summary>no such device exists</summary>
        internal const int PCAP_ERROR_NO_SUCH_DEVICE = -5;
        /// <summary>this device doesn't support rfmon (monitor) mode</summary>
        internal const int PCAP_ERROR_RFMON_NOTSUP = -6;
        /// <summary>operation supported only in monitor mode</summary>
        internal const int PCAP_ERROR_NOT_RFMON = -7;
        /// <summary>no permission to open the device</summary>
        internal const int PCAP_ERROR_PERM_DENIED = -8;
        /// <summary>interface isn't up</summary>
        internal const int PCAP_ERROR_IFACE_NOT_UP = -9;
        #endregion
    }
}
