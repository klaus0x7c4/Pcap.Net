using System;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using Microsoft.Win32.SafeHandles;
using PcapDotNet.Base;
using PcapDotNet.Packets;
using static PcapDotNet.Core.Native.PcapUnmanagedStructures;

namespace PcapDotNet.Core.Native
{
    internal class PcapWindowsPal : IPcapPal
    {
        private bool _breakloop;

        public PcapWindowsPal()
        {
            PcapHeaderSize = Marshal.SizeOf(typeof(pcap_pkthdr_windows));
            StringEncoding = ConfigureStringEncoding();
        }

        private static Encoding ConfigureStringEncoding()
        {
            try
            {
                // Try to change Libpcap to UTF-8 mode
                const uint PCAP_CHAR_ENC_UTF_8 = 1;
                var res = SafeNativeMethods.pcap_init(PCAP_CHAR_ENC_UTF_8, out var errorBuffer);
                if (res == 0)
                {
                    // We made it
                    return Encoding.UTF8;
                }

                throw new InvalidOperationException($"Failed to set pcap_init to UTF-8. Error: {errorBuffer.ToString(Encoding.Default)} ({res})");
            }
            catch (TypeLoadException)
            {
                // pcap_init not supported, using old Libpcap
                try
                {
                    var result = SafeNativeMethods.wsockinit(); // see https://man7.org/linux/man-pages/man3/pcap_init.3pcap.html Programs that don't call pcap_init() should, on Windows, call pcap_wsockinit() ..
                    if (result != 0)
                    {
                        throw new InvalidOperationException("Could not initialize Windows Sockets.");
                    }
                }
                catch (TypeLoadException)
                {
                    try
                    {
                        var result = SafeNativeMethods.pcap_wsockinit(); // see https://man7.org/linux/man-pages/man3/pcap_init.3pcap.html Programs that don't call pcap_init() should, on Windows, call pcap_wsockinit() ..
                        if (result != 0)
                        {
                            throw new InvalidOperationException("Could not initialize Windows Sockets.");
                        }
                    }
                    catch (TypeLoadException)
                    {
                        // no wpcap.dll present
                    }
                }
            }
#if NETCOREAPP2_0_OR_GREATER
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
#endif
            // In windows by default, system code page is used
            return Encoding.GetEncoding((int)SafeNativeMethods.GetOEMCP());
        }

        public Encoding StringEncoding { get; }

        public int PcapHeaderSize { get; }

        public IntPtr CreatePcapPacketHeaderHandle(Packet packet)
        {
            var header = new pcap_pkthdr_windows
            {
                caplen = packet.OriginalLength,
                len = (uint)packet.Length
            };
            var dt = packet.Timestamp.ToUniversalTime();
            var ts = dt - Interop.UnixEpoch;
            header.ts.tv_sec = (int)ts.TotalSeconds;
            header.ts.tv_usec = (int)((ts.TotalMilliseconds - 1000 * (double)header.ts.tv_sec) * 1000);

            var result = Marshal.AllocHGlobal(PcapHeaderSize);
            Marshal.StructureToPtr(header, result, true);
            return result;
        }

        public unsafe PcapPacketHeader CreatePcapPacketHeader(IntPtr /* pcap_pkthdr* */ ptr)
        {
            var pcap_header = (pcap_pkthdr_windows*)ptr;
            var timestamp = PacketTimestamp.PcapTimestampToDateTime(pcap_header->ts);
            return new PcapPacketHeader(timestamp, pcap_header->caplen, pcap_header->len);
        }

        public PcapInterfaceHandle GetAllLocalMachine()
        {
            var handle = new PcapInterfaceHandle();
            var auth = default(pcap_rmtauth); //auth is not needed

            var result = pcap_findalldevs_ex(Pcap.PCAP_SRC_IF_STRING, ref auth, ref handle, out var errbuf);
            if (result < 0)
            {
                PcapError.ThrowInvalidOperation($"Failed getting devices. Error: {errbuf}", null);
            }
            return handle;
        }
        public NetworkInterface[] GetAllNetworkInterfacesByDotNet()
        {
            return NetworkInterface.GetAllNetworkInterfaces();
        }

        public PacketTotalStatistics GetTotalStatistics(PcapHandle pcapDescriptor)
        {
            int statisticsSize = 0;
            var statisticsPtr = SafeNativeMethods.pcap_stats_ex(pcapDescriptor, ref statisticsSize);
            if (statisticsPtr == IntPtr.Zero)
                PcapError.ThrowInvalidOperation("Failed getting total statistics", pcapDescriptor);

            return new PacketTotalStatistics(statisticsPtr, statisticsSize);
        }

        public int pcap_activate(PcapHandle p)
        {
            return SafeNativeMethods.pcap_activate(p);
        }

        public int pcap_breakloop(PcapHandle p)
        {
            _breakloop = true;
            return SafeNativeMethods.pcap_breakloop(p);
        }

        public void pcap_close(IntPtr adaptHandle)
        {
            SafeNativeMethods.pcap_close(adaptHandle);
        }

        public int pcap_compile(PcapHandle adaptHandle, IntPtr fp, string str, int optimize, uint netmask)
        {
            return SafeNativeMethods.pcap_compile(adaptHandle, fp, str, optimize, netmask);
        }

        public PcapHandle pcap_create(string dev, out string errbuf)
        {
            var result = SafeNativeMethods.pcap_create(dev, out var errorBuffer);
            errbuf = errorBuffer.ToString();
            return result;
        }

        public int pcap_datalink(PcapHandle adaptHandle)
        {
            return SafeNativeMethods.pcap_datalink(adaptHandle);
        }

        public int pcap_datalink_name_to_val(string name)
        {
            return SafeNativeMethods.pcap_datalink_name_to_val(name);
        }

        public string pcap_datalink_val_to_description(int dlt)
        {
            return SafeNativeMethods.pcap_datalink_val_to_description(dlt);
        }

        public string pcap_datalink_val_to_description_or_dlt(int dlt)
        {
            return SafeNativeMethods.pcap_datalink_val_to_description_or_dlt(dlt);
        }

        public string pcap_datalink_val_to_name(int dlt)
        {
            return SafeNativeMethods.pcap_datalink_val_to_name(dlt);
        }

        public int pcap_dispatch(PcapHandle adaptHandle, int count, pcap_handler callback, IntPtr ptr, out bool breakloop)
        {
            var result = SafeNativeMethods.pcap_dispatch(adaptHandle, count, callback, ptr);
            breakloop = _breakloop;
            _breakloop = false;
            return result;
        }

        public void pcap_dump(IntPtr user, IntPtr h, IntPtr sp)
        {
            SafeNativeMethods.pcap_dump(user, h, sp);
        }

        public void pcap_dump_close(IntPtr p)
        {
            SafeNativeMethods.pcap_dump_close(p);
        }

        public IntPtr pcap_dump_file(IntPtr p)
        {
            return SafeNativeMethods.pcap_dump_file(p);
        }

        public int pcap_dump_flush(IntPtr p)
        {
            return SafeNativeMethods.pcap_dump_flush(p);
        }

        public long pcap_dump_ftell(IntPtr pcapDumper)
        {
            return SafeNativeMethods.pcap_dump_ftell(pcapDumper);
        }

        public IntPtr pcap_dump_open(PcapHandle adaptHandle, string fname)
        {
            return SafeNativeMethods.pcap_dump_open(adaptHandle, fname);
        }

        public int pcap_fileno(PcapHandle adapter)
        {
            return SafeNativeMethods.pcap_fileno(adapter);
        }

        public int pcap_findalldevs(ref PcapInterfaceHandle alldevs, out string errbuf)
        {
            var result = SafeNativeMethods.pcap_findalldevs(ref alldevs, out var errorBuffer);
            errbuf = errorBuffer.ToString();
            return result;
        }

        public int pcap_findalldevs_ex(string source, ref pcap_rmtauth auth, ref PcapInterfaceHandle alldevs, out string errbuf)
        {
            var result = SafeNativeMethods.pcap_findalldevs_ex(source, ref auth, ref alldevs, out var errorBuffer);
            errbuf = errorBuffer.ToString();
            return result;
        }

        public void pcap_freealldevs(IntPtr alldevs)
        {
            SafeNativeMethods.pcap_freealldevs(alldevs);
        }

        public void pcap_freecode(IntPtr fp)
        {
            SafeNativeMethods.pcap_freecode(fp);
        }

        public string pcap_geterr(PcapHandle adaptHandle)
        {
            return SafeNativeMethods.pcap_geterr(adaptHandle);
        }

        public int pcap_getnonblock(PcapHandle adaptHandle, out string errbuf)
        {
            var result = SafeNativeMethods.pcap_getnonblock(adaptHandle, out var errorBuffer);
            errbuf = errorBuffer.ToString();
            return result;
        }

        public int pcap_get_selectable_fd(PcapHandle adaptHandle)
        {
            return SafeNativeMethods.pcap_get_selectable_fd(adaptHandle);
        }

        public string pcap_lib_version()
        {
            return SafeNativeMethods.pcap_lib_version();
        }

        public int pcap_next_ex(PcapHandle adaptHandle, ref IntPtr header, ref IntPtr data)
        {
            var result =  SafeNativeMethods.pcap_next_ex(adaptHandle, ref header, ref data);
            _breakloop = false;
            return result;
        }

        public int pcap_offline_filter(IntPtr prog, IntPtr header, IntPtr pkt_data)
        {
            return SafeNativeMethods.pcap_offline_filter(prog, header, pkt_data);
        }

        public PcapHandle pcap_open(string dev, int packetLen, int flags, int read_timeout, ref pcap_rmtauth rmtauth, out string errbuf)
        {
            var handle = SafeNativeMethods.pcap_open(dev, packetLen, flags, read_timeout, ref rmtauth, out var errorBuffer);
            errbuf = errorBuffer.ToString();
            return handle;
        }

        public PcapHandle pcap_open_dead(int linktype, int snaplen)
        {
            return SafeNativeMethods.pcap_open_dead(linktype, snaplen);
        }

        public PcapHandle pcap_open_offline(string fname, out string errbuf)
        {
            errbuf = "";
            PcapHandle handle;
            if (fname.AreAllCharactersInRange((char)0, (char)255))
            {
                handle = SafeNativeMethods.pcap_open_offline(fname, out var errorBuffer);
                errbuf = errorBuffer.ToString();
            }
            else
            {
                try
                {
                    var file = File.OpenRead(fname);
                    handle = SafeNativeMethods.pcap_hopen_offline(file.SafeFileHandle, out var errorBuffer);
                    errbuf = errorBuffer.ToString();

                    if (handle.IsInvalid)
                    {
                        file.Close();
                    }
                }
                catch (FileNotFoundException)
                {
                    handle = new PcapHandle();
                }
            }

            return handle;
        }

        public int pcap_sendpacket(PcapHandle adaptHandle, IntPtr data, int size)
        {
            return SafeNativeMethods.pcap_sendpacket(adaptHandle, data, size);
        }

        public int pcap_setfilter(PcapHandle adaptHandle, IntPtr fp)
        {
            return SafeNativeMethods.pcap_setfilter(adaptHandle, fp);
        }

        public int pcap_setnonblock(PcapHandle adaptHandle, int nonblock, out string errbuf)
        {
            var result = SafeNativeMethods.pcap_setnonblock(adaptHandle, nonblock, out var errorBuffer);
            errbuf = errorBuffer.ToString();
            return result;
        }

        public int pcap_set_buffer_size(PcapHandle adapter, int bufferSizeInBytes)
        {
            return SafeNativeMethods.pcap_set_buffer_size(adapter, bufferSizeInBytes);
        }

        public int pcap_set_promisc(PcapHandle p, int promisc)
        {
            return SafeNativeMethods.pcap_set_promisc(p, promisc);
        }

        public int pcap_set_rfmon(PcapHandle p, int rfmon)
        {
            return SafeNativeMethods.pcap_set_rfmon(p, rfmon);
        }

        public int pcap_set_snaplen(PcapHandle p, int snaplen)
        {
            return SafeNativeMethods.pcap_set_snaplen(p, snaplen);
        }

        public int pcap_set_timeout(PcapHandle p, int to_ms)
        {
            return SafeNativeMethods.pcap_set_timeout(p, to_ms);
        }

        public int pcap_snapshot(PcapHandle adapter)
        {
            return SafeNativeMethods.pcap_snapshot(adapter);
        }

        public int pcap_stats(PcapHandle adapter, IntPtr stat)
        {
            return SafeNativeMethods.pcap_stats(adapter, stat);
        }

        public int pcap_set_datalink(PcapHandle adaptHandle, int dlt)
        {
            return SafeNativeMethods.pcap_set_datalink(adaptHandle, dlt);
        }

        public int pcap_list_datalinks(PcapHandle adaptHandle, ref IntPtr dataLinkList)
        {
            return SafeNativeMethods.pcap_list_datalinks(adaptHandle, ref dataLinkList);
        }

        public void pcap_free_datalinks(IntPtr dataLinkList)
        {
            SafeNativeMethods.pcap_free_datalinks(dataLinkList);
        }

        public int pcap_loop(PcapHandle adaptHandle, int count, pcap_handler callback, IntPtr ptr)
        {
            var result = SafeNativeMethods.pcap_loop(adaptHandle, count, callback, ptr);
            _breakloop = false;
            return result;
        }

        public int pcap_is_swapped(PcapHandle adapter)
        {
            return SafeNativeMethods.pcap_is_swapped(adapter);
        }

        public int pcap_major_version(PcapHandle adapter)
        {
            return SafeNativeMethods.pcap_major_version(adapter);
        }

        public int pcap_minor_version(PcapHandle adapter)
        {
            return SafeNativeMethods.pcap_minor_version(adapter);
        }

        public int pcap_setmode(PcapHandle adapter, PacketCommunicatorMode mode)
        {
            return SafeNativeMethods.pcap_setmode(adapter, (int)mode);
        }

        public int pcap_setbuff(PcapHandle adapter, int dim)
        {
            return SafeNativeMethods.pcap_setbuff(adapter, dim);
        }

        public int pcap_setmintocopy(PcapHandle adapter, int size)
        {
            return SafeNativeMethods.pcap_setmintocopy(adapter, size);
        }

        public IntPtr pcap_setsampling(PcapHandle adapter)
        {
            return SafeNativeMethods.pcap_setsampling(adapter);
        }

        public int pcap_sendqueue_transmit(PcapHandle p, ref pcap_send_queue queue, int sync)
        {
            return SafeNativeMethods.pcap_sendqueue_transmit(p, ref queue, sync);
        }

        /// <summary>
        /// Per http://msdn.microsoft.com/en-us/ms182161.aspx
        /// </summary>
        [SuppressUnmanagedCodeSecurity]
        private static class SafeNativeMethods
        {
            private const string PCAP_DLL = "wpcap";

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool SetDllDirectory(string lpPathName);

            [DllImport("kernel32.dll")]
            internal static extern uint GetOEMCP();

            static SafeNativeMethods()
            {
                SetDllDirectory(Path.Combine(Environment.SystemDirectory, "Npcap"));
            }

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int wsockinit();

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_wsockinit(); // name in older npcap versions

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal static extern int pcap_init(uint opts, out PcapErrorBuffer /* char* */ errbuf);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_findalldevs(ref PcapInterfaceHandle /* pcap_if_t** */ alldevs, out PcapErrorBuffer /* char* */ errbuf);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_findalldevs_ex(
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] string /* char* */source,
                ref pcap_rmtauth /* pcap_rmtauth* */auth,
                ref PcapInterfaceHandle /* pcap_if_t** */alldevs,
                out PcapErrorBuffer /* char* */ errbuf);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static void pcap_freealldevs(IntPtr /* pcap_if_t* */ alldevs);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static PcapHandle /* pcap_t* */ pcap_create(
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] string dev,
                out PcapErrorBuffer /* char* */ errbuf);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static PcapHandle /* pcap_t* */ pcap_open(
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] string dev,
                int packetLen,
                int flags,
                int read_timeout,
                ref pcap_rmtauth rmtauth,
                out PcapErrorBuffer /* char* */ errbuf);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            [SuppressUnmanagedCodeSecurity]
            internal static extern PcapHandle /* pcap_t* */ pcap_hopen_offline(
                SafeFileHandle/* FILE* */ fp,
                out PcapErrorBuffer /* char* */ errbuf);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static PcapHandle /* pcap_t* */ pcap_open_offline(
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] string/* const char* */ fname,
                out PcapErrorBuffer /* char* */ errbuf);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static PcapHandle /* pcap_t* */ pcap_open_dead(int linktype, int snaplen);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_set_buffer_size(PcapHandle /* pcap_t */ adapter, int bufferSizeInBytes);

            /// <summary>Open a file to write packets. </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static IntPtr /*pcap_dumper_t * */ pcap_dump_open(
                PcapHandle /*pcap_t * */adaptHandle,
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] string /*const char * */fname);

            /// <summary>
            ///  Save a packet to disk.
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static void pcap_dump(IntPtr /*u_char * */user, IntPtr /*const struct pcap_pkthdr * */h, IntPtr /*const u_char * */sp);

            /// <summary> close the files associated with p and deallocates resources.</summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static void pcap_close(IntPtr /*pcap_t **/adaptHandle);

            /// <summary>
            /// To avoid callback, this returns one packet at a time
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_next_ex(PcapHandle /* pcap_t* */ adaptHandle, ref IntPtr /* **pkt_header */ header, ref IntPtr data);

            /// <summary>
            /// Send a raw packet.<br/>
            /// This function allows to send a raw packet to the network. 
            /// The MAC CRC doesn't need to be included, because it is transparently calculated
            ///  and added by the network interface driver.
            /// </summary>
            /// <param name="adaptHandle">the interface that will be used to send the packet</param>
            /// <param name="data">contains the data of the packet to send (including the various protocol headers)</param>
            /// <param name="size">the dimension of the buffer pointed by data</param>
            /// <returns>0 if the packet is succesfully sent, -1 otherwise.</returns>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_sendpacket(PcapHandle /* pcap_t* */ adaptHandle, IntPtr data, int size);

            /// <summary>
            /// Compile a packet filter, converting an high level filtering expression (see Filtering expression syntax) in a program that can be interpreted by the kernel-level filtering engine. 
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_compile(
                PcapHandle /* pcap_t* */ adaptHandle,
                IntPtr /*bpf_program **/fp,
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] string /*char * */str,
                int optimize,
                UInt32 netmask);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_setfilter(PcapHandle /* pcap_t* */ adaptHandle, IntPtr /*bpf_program **/fp);

            /// <summary>
            /// Returns if a given filter applies to an offline packet. 
            /// </summary>
            /// <returns></returns>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_offline_filter(IntPtr /*bpf_program **/ prog, IntPtr /* pcap_pkthdr* */ header, IntPtr pkt_data);

            /// <summary>
            /// Free up allocated memory pointed to by a bpf_program struct generated by pcap_compile()
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static void pcap_freecode(IntPtr /*bpf_program **/fp);

            /// <summary>
            /// return the error text pertaining to the last pcap library error.
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler), MarshalCookie = PcapStringMarshaler.Cookie)]
            internal extern static string pcap_geterr(PcapHandle /*pcap_t * */ adaptHandle);

            /// <summary>Returns a pointer to a string giving information about the version of the libpcap library being used; note that it contains more information than just a version number. </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler), MarshalCookie = PcapStringMarshaler.Cookie)]
            internal extern static string /*const char **/  pcap_lib_version();

            /// <summary>return the standard I/O stream of the 'savefile' opened by pcap_dump_open().</summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static IntPtr /* FILE* */  pcap_dump_file(IntPtr /*pcap_dumper_t **/p);

            /// <summary>Flushes the output buffer to the 'savefile', so that any packets 
            /// written with pcap_dump() but not yet written to the 'savefile' will be written. 
            /// -1 is returned on error, 0 on success. </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_dump_flush(IntPtr /*pcap_dumper_t **/p);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static long pcap_dump_ftell(IntPtr /*pcap_dumper_t **/ pcapDumper);

            /// <summary>Closes a savefile. </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static void pcap_dump_close(IntPtr /*pcap_dumper_t **/p);

            /// <summary> Return the link layer of an adapter. </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_datalink(PcapHandle /* pcap_t* */ adaptHandle);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_datalink_name_to_val(
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] string /* const char* */ name);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler), MarshalCookie = PcapStringMarshaler.Cookie)]
            internal extern static string /* const char* */ pcap_datalink_val_to_description(int dlt);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler), MarshalCookie = PcapStringMarshaler.Cookie)]
            internal extern static string /* const char* */ pcap_datalink_val_to_description_or_dlt(int dlt);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler), MarshalCookie = PcapStringMarshaler.Cookie)]
            internal extern static string /* const char* */ pcap_datalink_val_to_name(int dlt);

            /// <summary>
            /// Set nonblocking mode. pcap_loop() and pcap_next() doesnt work in  nonblocking mode!
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_setnonblock(
                PcapHandle /* pcap_t* */ adaptHandle,
                int nonblock,
                out PcapErrorBuffer /* char* */ errbuf);

            /// <summary>
            /// Get nonblocking mode, returns allways 0 for savefiles.
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_getnonblock(
                PcapHandle /* pcap_t* */ adaptHandle,
                out PcapErrorBuffer /* char* */ errbuf);

            /// <summary>
            /// Read packets until cnt packets are processed or an error occurs.
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_dispatch(PcapHandle /* pcap_t* */ adaptHandle, int count, pcap_handler callback, IntPtr ptr);

            /// <summary>
            /// Retrieves a selectable file descriptor
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_get_selectable_fd(PcapHandle /* pcap_t* */ adaptHandle);

            /// <summary>
            /// Fills in the pcap_stat structure passed to the function
            /// based on the pcap_t adapter
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_stats(PcapHandle /* pcap_t* */ adapter, IntPtr /* struct pcap_stat* */ stat);

            /// <summary>
            /// pcap_stats_ex() extends the pcap_stats() allowing to return more statistical parameters than the old call. 
            /// One of the advantages of this new call is that the pcap_stat structure is not allocated by the user; instead, 
            /// it is returned back by the system. This allow to extend the pcap_stat structure without affecting backward 
            /// compatibility on older applications. These will simply check at the values of the members at the beginning 
            /// of the structure, while only newest applications are able to read new statistical values, which are appended in tail.
            /// To be sure not to read a piece of memory which has not been allocated by the system, the variable pcap_stat_size 
            /// will return back the size of the structure pcap_stat allocated by the system.
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static IntPtr /* struct pcap_stat* */ pcap_stats_ex(PcapHandle adapter, ref int pcapStatSize);

            /// <summary>
            /// Returns the snapshot length
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_snapshot(PcapHandle /* pcap_t* */ adapter);

            /// <summary>
            /// pcap_set_rfmon() sets whether monitor mode should be set on a capture handle when the handle is activated.
            /// If rfmon is non-zero, monitor mode will be set, otherwise it will not be set.  
            /// </summary>
            /// <returns>Returns 0 on success or PCAP_ERROR_ACTIVATED if called on a capture handle that has been activated.</returns>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_set_rfmon(PcapHandle /* pcap_t* */ p, int rfmon);

            /// <summary>
            /// pcap_set_snaplen() sets the snapshot length to be used on a capture handle when the handle is activated to snaplen.  
            /// </summary>
            /// <returns>Returns 0 on success or PCAP_ERROR_ACTIVATED if called on a capture handle that has been activated.</returns>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_set_snaplen(PcapHandle /* pcap_t* */ p, int snaplen);

            /// <summary>
            /// pcap_set_promisc() sets whether promiscuous mode should be set on a capture handle when the handle is activated. 
            /// If promisc is non-zero, promiscuous mode will be set, otherwise it will not be set.  
            /// </summary>
            /// <returns>Returns 0 on success or PCAP_ERROR_ACTIVATED if called on a capture handle that has been activated.</returns>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_set_promisc(PcapHandle /* pcap_t* */ p, int promisc);

            /// <summary>
            /// pcap_set_timeout() sets the packet buffer timeout that will be used on a capture handle when the handle is activated to to_ms, which is in units of milliseconds.
            /// </summary>
            /// <returns>Returns 0 on success or PCAP_ERROR_ACTIVATED if called on a capture handle that has been activated.</returns>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_set_timeout(PcapHandle /* pcap_t* */ p, int to_ms);

            /// <summary>
            /// pcap_activate() is used to activate a packet capture handle to look at packets on the network, with the options that were set on the handle being in effect.  
            /// </summary>
            /// <returns>Returns 0 on success without warnings, a non-zero positive value on success with warnings, and a negative value on error. A non-zero return value indicates what warning or error condition occurred.</returns>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_activate(PcapHandle /* pcap_t* */ p);

            /// <summary>
            /// Force a pcap_dispatch() or pcap_loop() call to return
            /// </summary>
            /// <returns>Returns 0 on success without warnings, a non-zero positive value on success with warnings, and a negative value on error. A non-zero return value indicates what warning or error condition occurred.</returns>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_breakloop(PcapHandle /* pcap_t* */ p);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_set_datalink(PcapHandle adaptHandle, int dlt);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_list_datalinks(PcapHandle adaptHandle, ref IntPtr dataLinkList);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static void pcap_free_datalinks(IntPtr dataLinkList);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_loop(PcapHandle adaptHandle, int count, pcap_handler callback, IntPtr ptr);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_is_swapped(PcapHandle adapter);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_major_version(PcapHandle adapter);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_minor_version(PcapHandle adapter);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_setmode(PcapHandle adapter, int mode);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_setbuff(PcapHandle adapter, int dim);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_setmintocopy(PcapHandle adapter, int size);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static IntPtr pcap_setsampling(PcapHandle adapter);

            #region libpcap specific
            /// <summary>
            /// Returns the file descriptor number from which captured packets are read,
            /// if a network device was opened with pcap_create() and pcap_activate() or
            /// with pcap_open_live(), or -1, if a ``savefile'' was opened with
            /// pcap_open_offline()
            /// Libpcap specific method
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_fileno(PcapHandle /*  pcap_t* */ adapter);
            #endregion

            #region Send queue functions

            /// <summary>
            /// Send a queue of raw packets to the network. 
            /// </summary>
            /// <param name="p"></param>
            /// <param name="queue"></param>
            /// <param name="sync">determines if the send operation must be synchronized: 
            /// if it is non-zero, the packets are sent respecting the timestamps, 
            /// otherwise they are sent as fast as possible</param>
            /// <returns>The amount of bytes actually sent. 
            /// If it is smaller than the size parameter, an error occurred 
            /// during the send. The error can be caused by a driver/adapter 
            /// problem or by an inconsistent/bogus send queue.</returns>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_sendqueue_transmit(PcapHandle /* pcap_t* */p, ref pcap_send_queue queue, int sync);

            #endregion
        }
    }
}
