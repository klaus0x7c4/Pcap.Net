using System;
using System.Net.NetworkInformation;
using System.Text;
using PcapDotNet.Packets;
using static PcapDotNet.Core.Native.PcapUnmanagedStructures;

namespace PcapDotNet.Core.Native
{
#pragma warning disable IDE1006 // Naming Styles
    public interface IPcapPal
    {
        Encoding StringEncoding { get; }

        /// <summary>
        /// Size of pcap_pkthdr struct in bytes
        /// </summary>
        int PcapHeaderSize { get; }

        /// <summary>
        /// Creates a platform depend pcap packet header.handle
        /// </summary>
        /// <remarks>MUST be freed with <see cref="Marshal.FreeHGlobal(IntPtr)"/>!</remarks>
        /// <returns>Pointer to the header structure</returns>
        IntPtr CreatePcapPacketHeaderHandle(Packet packet);

        /// <summary>
        /// Creates a PcapPacketHeader object from platform depend unmanaged structure
        /// </summary>
        /// <param name="ptr">pointer to platform depend structure of pcap_pkthdr</param>
        PcapPacketHeader CreatePcapPacketHeader(IntPtr /* pcap_pkthdr* */ ptr);

        /// <returns>NULL or pointer to the first pcap_if_t entry</returns>
        /// <exception cref="InvalidOperationException">if native libpcap call respond an error</exception>
        PcapInterfaceHandle GetAllLocalMachine();

        NetworkInterface[] GetAllNetworkInterfacesByDotNet();

        PacketTotalStatistics GetTotalStatistics(PcapHandle pcapDescriptor);

        int pcap_findalldevs(ref PcapInterfaceHandle /* pcap_if_t** */ alldevs, out string /* char* */ errbuf);

        void pcap_freealldevs(IntPtr /* pcap_if_t * */ alldevs);

        /// <summary>
        /// Extended pcap_open() method that is Npcap/Winpcap specific that
        /// provides extra flags and functionality
        /// See http://www.winpcap.org/docs/docs_40_2/html/group__wpcapfunc.html#g2b64c7b6490090d1d37088794f1f1791
        /// </summary>
        PcapHandle /* pcap_t* */ pcap_open(
            string dev,
            int packetLen,
            int flags,
            int read_timeout,
            ref pcap_rmtauth rmtauth,
            out string errbuf);

        PcapHandle /* pcap_t* */ pcap_create(string dev, out string errbuf);

        PcapHandle /* pcap_t* */ pcap_open_offline(string/*const char* */ fname, out string /* char* */ errbuf);


        /// <summary>
        /// Open a fake pcap_t for compiling filters or opening a capture for output.
        /// </summary>
        /// <param name="linktype">Specifies the link-layer type for the pcap_t</param>
        /// <param name="snaplen">Specifies the snapshot length for the pcap_t</param>
        /// <returns>An IntPtr to a pcap_t structure</returns>
        PcapHandle /* pcap_t* */ pcap_open_dead(int linktype, int snaplen);

        /// <summary>Open a file to write packets. </summary>
        IntPtr /*pcap_dumper_t * */ pcap_dump_open(PcapHandle /*pcap_t * */adaptHandle, string /*const char* */fname);

        /// <summary>
        /// Get the current file offset for a savefile being written.
        /// </summary>
        /// <returns>The current file position for the 'savefile', representing the number of bytes written by pcap_dump_open() and pcap_dump(). -1 is returned on error.</returns>
        long pcap_dump_ftell(IntPtr /* pcap_dumper_t* */ pcapDumper);

        /// <summary>
        /// Outputs a packet to the 'savefile' opened with pcap_dump_open(). Note that its calling arguments are suitable for use with pcap_dispatch() or pcap_loop().
        /// </summary>
        /// <param name="user">If called directly, the user parameter is of type pcap_dumper_t as returned by pcap_dump_open().</param>
        void pcap_dump(IntPtr /*u_char * */user, IntPtr /*const struct pcap_pkthdr * */ header, IntPtr /*const u_char * */ data);

        /// <summary> close the files associated with <paramref name="adaptHandle"/> and deallocates resources.</summary>
        void pcap_close(IntPtr /*pcap_t **/adaptHandle);

        /// <summary>
        /// To avoid callback, this returns one packet at a time
        /// </summary>
        int pcap_next_ex(PcapHandle /* pcap_t* */ adaptHandle, ref IntPtr /* **pkt_header */ header, ref IntPtr data);

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
        int pcap_sendpacket(PcapHandle /* pcap_t* */ adaptHandle, IntPtr data, int size);

        /// <summary>
        /// Compile a packet filter, converting an high level filtering expression (see Filtering expression syntax) in a program that can be interpreted by the kernel-level filtering engine. 
        /// </summary>
        /// <returns>0 on success and -1 on failure</returns>
        int pcap_compile(PcapHandle /* pcap_t* */ adaptHandle, IntPtr /*bpf_program **/fp, string /*char * */str, int optimize, UInt32 netmask);

        int pcap_setfilter(PcapHandle /* pcap_t* */ adaptHandle, IntPtr /*bpf_program **/fp);

        /// <summary>
        /// Check whether a filter matches a packet. 
        /// </summary>
        /// <returns>
        /// This will be zero if the packet doesn't match the filter and non-zero if the packet matches the filter. 
        /// </returns>
        int pcap_offline_filter(IntPtr /*bpf_program **/ prog, IntPtr /* pcap_pkthdr* */ header, IntPtr pkt_data);

        /// <summary>
        /// Free up allocated memory pointed to by a bpf_program struct generated by pcap_compile()
        /// </summary>
        void pcap_freecode(IntPtr /*bpf_program **/fp);

        /// <summary>
        /// return the error text pertaining to the last pcap library error.
        /// </summary>
        string pcap_geterr(PcapHandle /*pcap_t * */ adaptHandle);

        /// <summary>Returns a pointer to a string giving information about the version of the libpcap library being used; note that it contains more information than just a version number. </summary>
        string /*const char* */  pcap_lib_version();

        /// <summary>return the standard I/O stream of the 'savefile' opened by pcap_dump_open().</summary>
        IntPtr /*FILE **/  pcap_dump_file(IntPtr /*pcap_dumper_t **/p);

        /// <summary>Flushes the output buffer to the 'savefile', so that any packets 
        /// written with pcap_dump() but not yet written to the 'savefile' will be written. 
        /// -1 is returned on error, 0 on success. </summary>
        int pcap_dump_flush(IntPtr /*pcap_dumper_t **/p);

        /// <summary>Closes a savefile. </summary>
        void pcap_dump_close(IntPtr /*pcap_dumper_t **/p);

        /// <summary> Return the link layer of an adapter. </summary>
        int pcap_datalink(PcapHandle /* pcap_t* */ adaptHandle);

        /// <summary>
        /// set the link-layer header type to be used by a capture device
        /// </summary>
        /// <param name="dlt">new link-layer header type of the pcap descriptor which should be used</param>
        /// <returns>0 on success, PCAP_ERROR_NOT_ACTIVATED if called on a capture handle that has been created but not activated, or PCAP_ERROR on other errors. If PCAP_ERROR is returned, pcap_geterr(3PCAP) or pcap_perror(3PCAP) may be called with p as an argument to fetch or display the error text.</returns>
        int pcap_set_datalink(PcapHandle /* pcap_t* */ adaptHandle, int dlt);

        /// <summary>
        /// Is used to get a list of the supported link-layer header types of the interface associated with the pcap descriptor. pcap_list_datalinks() allocates an array to hold the list and sets *dataLinkList to point to that array.
        /// The caller is responsible for freeing the array with pcap_free_datalinks(), which frees the list of link-layer header types pointed to by dataLinkList.
        /// It must not be called on a pcap descriptor created by pcap_create(3PCAP) that has not yet been activated by pcap_activate(3PCAP).
        /// </summary>
        /// <param name="dataLinkList">list of link-layer header types supported by a capture device</param>
        /// <returns>The number of link-layer header types in the array on success, PCAP_ERROR_NOT_ACTIVATED if called on a capture handle that has been created but not activated, and PCAP_ERROR on other errors. If PCAP_ERROR is returned, pcap_geterr(3PCAP) or pcap_perror(3PCAP) may be called with p as an argument to fetch or display the error text.</returns>
        int pcap_list_datalinks(PcapHandle /* pcap_t* */ adaptHandle, ref IntPtr /* int** */ dataLinkList);

        /// <summary>
        /// Frees the list of link-layer header types pointed to by dataLinkList.
        /// </summary>
        void pcap_free_datalinks(IntPtr /* int* */ dataLinkList);

        /// <summary>
        /// Get the link-layer header type value corresponding to a header type name.
        /// Translates a link-layer header type name, which is a DLT_ name with the DLT_ removed,
        /// to the corresponding link-layer header type value.The translation is case-insensitive.
        /// </summary>
        /// <returns>Returns the type value on success and PCAP_ERROR if the name is not a known type name.</returns>
        int pcap_datalink_name_to_val(string /*const char* */ name);

        /// <summary>
        /// Translates a link-layer header type value to the corresponding link-layer header type name,
        /// which is the DLT_ name for the link-layer header type value with the DLT_ removed.
        /// NULL is returned if the type value does not correspond to a known DLT_ value.
        /// </summary>
        string /* const char* */ pcap_datalink_val_to_name(int dlt);

        /// <summary>
        /// Translates a link-layer header type value to a short description of that link-layer header type.
        /// NULL is returned if the type value does not correspond to a known DLT_ value.
        /// </summary>
        string /* const char* */ pcap_datalink_val_to_description(int dlt);

        /// <summary>
        /// Translates a link-layer header type value to a short description of that link-layer header type 
        /// just like pcap_datalink_val_to_description. If the type value does not correspond to a known DLT_ value,
        /// the string "DLT n" is returned, where n is the value of the dlt argument.
        /// </summary>
        string /* const char* */ pcap_datalink_val_to_description_or_dlt(int dlt);

        /// <summary>
        /// Set nonblocking mode. pcap_loop() and pcap_next() doesnt work in  nonblocking mode!
        /// </summary>
        int pcap_setnonblock(PcapHandle /* pcap_t* */ adaptHandle, int nonblock, out string /* char* */ errbuf);

        /// <summary>
        /// Get nonblocking mode, returns allways 0 for savefiles.
        /// </summary>
        int pcap_getnonblock(PcapHandle /* pcap_t* */ adaptHandle, out string /* char* */ errbuf);

        /// <summary>
        /// Read packets until cnt packets are processed or an error occurs.
        /// </summary>
        int pcap_dispatch(PcapHandle /* pcap_t* */ adaptHandle, int count, pcap_handler callback, IntPtr ptr, out bool breakloop);

        /// <summary>
        /// Read packets until cnt packets are processed or an error occurs.
        /// </summary>
        int pcap_loop(PcapHandle /* pcap_t* */ adaptHandle, int count, pcap_handler callback, IntPtr ptr);

        /// <summary>
        /// Force a pcap_dispatch() or pcap_loop() call to return
        /// </summary>
        /// <param name="p"></param>
        /// <returns></returns>
        int pcap_breakloop(PcapHandle /* pcap_t* */ p);

        /// <summary>
        /// Retrieves a selectable file descriptor
        /// </summary>
        int pcap_get_selectable_fd(PcapHandle /* pcap_t* */ adaptHandle);

        /// <summary>
        /// Fills in the pcap_stat structure passed to the function
        /// based on the pcap_t adapter
        /// </summary>
        int pcap_stats(PcapHandle /* pcap_t* */ adapter, IntPtr /* struct pcap_stat* */ stat);

        /// <summary>
        /// Returns the snapshot length
        /// </summary>
        int pcap_snapshot(PcapHandle /* pcap_t* */ adapter);

        /// <summary>
        /// find out whether a 'savefile' has the native byte order
        /// </summary>
        /// <returns>
        /// returns true (1) if p refers to a 'savefile' that uses a different byte order than the current system. For a live capture, it always returns false (0). Returns PCAP_ERROR_NOT_ACTIVATED if called on a capture handle that has been created but not activated.
        /// </returns>
        int pcap_is_swapped(PcapHandle /* pcap_t* */ adapter);

        /// <summary>
        /// The version number of a 'savefile'
        /// </summary>
        /// <returns>The major number of the file format of the 'savefile'</returns>
        /// <remarks>
        /// The version number is stored in the 'savefile'; note that the meaning of its values depends on the type of 'savefile' (for example, pcap or pcapng).
        /// If p refers to a live capture, the values returned by pcap_major_version() and pcap_minor_version() are not meaningful.
        /// </remarks>
        int pcap_major_version(PcapHandle /* pcap_t* */ adapter);

        /// <summary>
        /// The version number of a 'savefile'
        /// </summary>
        /// <returns>The minor number of the file format of the 'savefile'</returns>
        /// <remarks>
        /// The version number is stored in the 'savefile'; note that the meaning of its values depends on the type of 'savefile' (for example, pcap or pcapng).
        /// If p refers to a live capture, the values returned by pcap_major_version() and pcap_minor_version() are not meaningful.
        /// </remarks>
        int pcap_minor_version(PcapHandle /* pcap_t* */ adapter);

        /// <summary>
        /// pcap_set_rfmon() sets whether monitor mode should be set on a capture handle when the handle is activated.
        /// If rfmon is non-zero, monitor mode will be set, otherwise it will not be set.  
        /// </summary>
        /// <returns>Returns 0 on success or PCAP_ERROR_ACTIVATED if called on a capture handle that has been activated.</returns>
        int pcap_set_rfmon(PcapHandle /* pcap_t* */ p, int rfmon);

        /// <summary>
        /// pcap_set_snaplen() sets the snapshot length to be used on a capture handle when the handle is activated to snaplen.  
        /// </summary>
        /// <returns>Returns 0 on success or PCAP_ERROR_ACTIVATED if called on a capture handle that has been activated.</returns>
        int pcap_set_snaplen(PcapHandle /* pcap_t* */ p, int snaplen);

        /// <summary>
        /// pcap_set_promisc() sets whether promiscuous mode should be set on a capture handle when the handle is activated. 
        /// If promisc is non-zero, promiscuous mode will be set, otherwise it will not be set.  
        /// </summary>
        /// <returns>Returns 0 on success or PCAP_ERROR_ACTIVATED if called on a capture handle that has been activated.</returns>
        int pcap_set_promisc(PcapHandle /* pcap_t* */ p, int promisc);

        /// <summary>
        /// pcap_set_timeout() sets the packet buffer timeout that will be used on a capture handle when the handle is activated to to_ms, which is in units of milliseconds.
        /// </summary>
        /// <returns>Returns 0 on success or PCAP_ERROR_ACTIVATED if called on a capture handle that has been activated.</returns>
        int pcap_set_timeout(PcapHandle /* pcap_t* */ p, int to_ms);

        /// <summary>
        /// pcap_activate() is used to activate a packet capture handle to look at packets on the network, with the options that were set on the handle being in effect.
        /// </summary>
        /// <returns>Returns 0 on success without warnings, a non-zero positive value on success with warnings, and a negative value on error. A non-zero return value indicates what warning or error condition occurred.</returns>
        int pcap_activate(PcapHandle /* pcap_t* */ p);

        #region libpcap specific
        /// <summary>
        /// Returns the file descriptor number from which captured packets are read,
        /// if a network device was opened with pcap_create() and pcap_activate() or
        /// with pcap_open_live(), or -1, if a ``savefile'' was opened with
        /// pcap_open_offline()
        /// Libpcap specific method
        /// </summary>
        int pcap_fileno(PcapHandle /* pcap_t* p */ adapter);

        #endregion

        #region Windows-specific Extensions (win pcap)
        /// <summary>
        /// Set the working mode of the interface p to mode. 
        /// </summary>
        int pcap_setmode(PcapHandle /* pcap_t* p */ adapter, PacketCommunicatorMode mode);

        /// <summary>
        /// Set the size of the kernel buffer associated with an adapter.
        /// </summary>
        int pcap_setbuff(PcapHandle /* pcap_t* p */ adapter, int dim);

        /// <summary>
        /// Set the minumum amount of data received by the kernel in a single call.
        /// </summary>
        int pcap_setmintocopy(PcapHandle /* pcap_t* p */ adapter, int size);

        /// <summary>
        /// Define a sampling method for packet capture. This function allows applying a sampling method to the packet capture process.The currently sampling methods (and the way to set them) are described into the struct pcap_samp. In other words, the user must set the appropriate parameters into it; these will be applied as soon as the capture starts.
        /// </summary>
        /// <remarks>
        /// Sampling parameters cannot be changed when a capture is active. These parameters must be applied before starting the capture. If they are applied when the capture is in progress, the new settings are ignored.
        /// Sampling works only when capturing data on Win32 or reading from a file.It has not been implemented on other platforms.Sampling works on remote machines provided that the probe (i.e.the capturing device) is a Win32 workstation.
        /// </remarks>
        IntPtr /* struct pcap_samp* */ pcap_setsampling(PcapHandle /* pcap_t* p */ adapter);
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
        /// <remarks>Windows only</remarks>
        int pcap_sendqueue_transmit(PcapHandle /*pcap_t * */ p, ref pcap_send_queue queue, int sync);

        #endregion
    }
#pragma warning restore IDE1006 // Naming Styles
}
