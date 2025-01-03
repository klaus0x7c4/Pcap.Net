using System;
using System.Runtime.InteropServices;
using System.Text;

namespace PcapDotNet.Core.Native
{
    // Taken from: sharppcap/SharpPcap/LibPcap/LibPcapSafeNativeMethods.Encoding.cs
    /// <summary>
    /// Helper class to marshall string depending on encoding used by Libpcap
    /// </summary>
    internal class PcapStringMarshaler : ICustomMarshaler
    {
        public const string Cookie = "no_free";

        public static ICustomMarshaler GetInstance(string cookie)
        {
            return new PcapStringMarshaler(cookie);
        }

        private readonly bool _freeOnClean;

        public PcapStringMarshaler(string cookie)
        {
            // If the string was not allocated by us, don't free it
            _freeOnClean = !cookie.Contains(Cookie);
        }

        public void CleanUpManagedData(object managedObj)
        {
            // Nothing to clean
        }

        public void CleanUpNativeData(IntPtr nativeData)
        {
            if (_freeOnClean)
            {
                Marshal.FreeHGlobal(nativeData);
            }
        }

        public int GetNativeDataSize()
        {
            return -1;
        }

        public IntPtr MarshalManagedToNative(object managedObj)
        {
            if (managedObj is null)
            {
                return IntPtr.Zero;
            }
            var str = (string)managedObj;
            var bytes = GetEncoding().GetBytes(str);
            var ptr = Marshal.AllocHGlobal(bytes.Length + 1);
            Marshal.Copy(bytes, 0, ptr, bytes.Length);
            // Put zero string termination
            Marshal.WriteByte(ptr + bytes.Length, 0);
            return ptr;
        }

        public unsafe object MarshalNativeToManaged(IntPtr nativeData)
        {
            if (nativeData == IntPtr.Zero)
            {
                return null;
            }
            var bytes = (byte*)nativeData;
            var nbBytes = 0;
            while (*(bytes + nbBytes) != 0)
            {
                nbBytes++;
            }
#if NETCOREAPP1_1_OR_GREATER
            return GetEncoding().GetString(bytes, nbBytes);
#else
            var byteArray = new byte[nbBytes];
            Marshal.Copy((IntPtr)bytes, byteArray, 0, nbBytes);
            return GetEncoding().GetString(byteArray);
#endif
        }

        internal static Encoding GetEncoding()
        {
            // HACK: while init Interop (static ctor) PcapPal is maybe null.
            // create the windows PAL pcap_init is called and we need encoding either way
            // whats a better solution here???
            return Interop.Pcap?.StringEncoding ?? Encoding.Default;
        }
    }
}
