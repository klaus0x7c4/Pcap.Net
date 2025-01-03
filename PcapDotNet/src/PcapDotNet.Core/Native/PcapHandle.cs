using Microsoft.Win32.SafeHandles;

namespace PcapDotNet.Core.Native
{
    /// <summary>
    /// Wrap a pointer/handle to a native <c>pcap_t</c> struct
    /// </summary>
    public class PcapHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public PcapHandle() : base(ownsHandle: true) { }

        /// <summary>
        /// Unix specific.
        /// </summary>
        internal int FileDescriptor { get; set; }
        /// <summary>
        /// Unix specific.
        /// </summary>
        internal int Timeout { get; set; }

        protected override bool ReleaseHandle()
        {
            Interop.Pcap.pcap_close(handle);
            return true;
        }
    }
}
