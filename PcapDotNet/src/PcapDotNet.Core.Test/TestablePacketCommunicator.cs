using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using PcapDotNet.Base;
using PcapDotNet.Core.Native;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;

namespace PcapDotNet.Core.Test
{
    [ExcludeFromCodeCoverage]
    internal sealed class TestableOfflinePacketDevice : PacketDevice
    {
        private readonly string _fileName;

        public TestableOfflinePacketDevice(string fileName)
        {
            _fileName = fileName;
        }
        public override string Name { get; }
        public override string Description { get; }
        public override DeviceAttributes Attributes { get; }
        public override ReadOnlyCollection<DeviceAddress> Addresses { get; }
        public override PacketCommunicator Open(int snapshotLength, PacketDeviceOpenAttributes attributes, int readTimeout)
        {
            return new TestablePacketCommunicator(_fileName);
        }
    }

    [ExcludeFromCodeCoverage]
    internal sealed class TestablePacketCommunicator : PacketCommunicator
    {
        public TestablePacketCommunicator(string filename)
            : base(null)
        {
            _offlineRead = true;
            PcapDescriptor = Interop.Pcap.pcap_open_offline(filename, out var errorBuffer);
            if (PcapDescriptor.IsInvalid)
            {
                throw new InvalidOperationException($"Failed opening file {filename}. Error: {errorBuffer}.");
            }
        }

        public TestablePacketCommunicator(int snapshotLength, PacketDeviceOpenAttributes attributes, int readTimeout)
            : base(null)
        {
            PcapUnmanagedStructures.pcap_rmtauth auth = default;
            PcapDescriptor = Interop.Pcap.pcap_open("dev name", snapshotLength, (int)attributes, readTimeout, ref auth, out _);
        }

        public override PacketTotalStatistics TotalStatistics
        {
            get
            {
                if (_offlineRead)
                    throw new InvalidOperationException("Can't get " + nameof(PacketTotalStatistics) + " for offline devices");

                return Interop.Pcap.GetTotalStatistics(PcapDescriptor);
            }
        }

        public override void Transmit(PacketSendBuffer sendBuffer, bool isSync)
        {
            if (_offlineRead)
                throw new InvalidOperationException("Can't transmit queue to an offline device");
            if (sendBuffer is null)
                throw new ArgumentNullException(nameof(sendBuffer));

            var transmit = typeof(PacketSendBuffer).GetMethod("Transmit", BindingFlags.NonPublic | BindingFlags.Instance);
            transmit.Invoke(sendBuffer, new object[] { PcapDescriptor, isSync });
        }
    }

    internal sealed class TestablePcapInterfaceHandle : PcapInterfaceHandle
    {
        private List<PcapUnmanagedStructures.pcap_if> _networkAdapters;

        public TestablePcapInterfaceHandle(bool winpcapMode, string adapterId)
        {
            _networkAdapters = new List<PcapUnmanagedStructures.pcap_if>();
            handle = new IntPtr(1);
            var isWindows = Environment.OSVersion.Platform != PlatformID.Unix && Environment.OSVersion.Platform != PlatformID.MacOSX;
            var adapterName = isWindows ? @"rpcap://\Device\NPF_" + adapterId : adapterId;
            if (winpcapMode)
            {
                _networkAdapters.Add(new PcapUnmanagedStructures.pcap_if { Name = adapterName });
            }
            else
            {
                _networkAdapters.Add(new PcapUnmanagedStructures.pcap_if
                                     {
                                         Name = adapterName,
                                         Flags = (uint)(DeviceAttributes.Up | DeviceAttributes.Running | DeviceAttributes.ConnectionStatusConnected),
                                         Next = new IntPtr(2)
                                     });
                _networkAdapters.Add(new PcapUnmanagedStructures.pcap_if { Name = isWindows ? @"rpcap://\Device\NPF_Loopback" : "lo", Flags = (uint)DeviceAttributes.Loopback });
            }
        }

        public override IEnumerable<PcapUnmanagedStructures.pcap_if> GetManagedData()
        {
            var nextDevPtr = handle;
            while (nextDevPtr != IntPtr.Zero)
            {
                var pcap_if = _networkAdapters[nextDevPtr.ToInt32() - 1];
                yield return pcap_if;
                nextDevPtr = pcap_if.Next;
            }
        }
    }

    internal sealed class TestablePcapHandle : PcapHandle
    {
        public TestablePcapHandle(string path = null)
        {
            IsOffline = path != null;
            Path = path;
            if (IsOffline)
                FileDesc = File.OpenRead(path);
            handle = new IntPtr(2);
        }

        public bool IsOffline { get; }
        public string Path { get; }
        public FileStream FileDesc { get; }

        protected override bool ReleaseHandle()
        {
            FileDesc?.Dispose();
            return base.ReleaseHandle();
        }
    }

    internal sealed class TestableNetworkInterface : NetworkInterface
    {
        private readonly NetworkInterfaceType _type;

        public TestableNetworkInterface(NetworkInterfaceType type)
        {
            _type = type;
            if (Environment.OSVersion.Platform != PlatformID.Unix && Environment.OSVersion.Platform != PlatformID.MacOSX)
            {
                Id = Guid.NewGuid().ToString();
                Name = type == NetworkInterfaceType.Loopback ? "Network adapter 'Adapter for loopback traffic capture' on local host" : "device with id " + Id;
            }
            else
            {
                if (type == NetworkInterfaceType.Loopback)
                    Name = Id = "lo";
                else
                    Name = Id = "eth0";
            }
            NetworkInterfaceType = type;
            OperationalStatus = OperationalStatus.Up;
        }

        public override IPInterfaceProperties GetIPProperties()
        {
            throw new NotImplementedException();
        }

        public override IPv4InterfaceStatistics GetIPv4Statistics()
        {
            throw new NotImplementedException();
        }

        public override PhysicalAddress GetPhysicalAddress()
        {
            return new PhysicalAddress(_type == NetworkInterfaceType.Loopback ? new byte[6] : new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 });
        }

        public override bool Supports(NetworkInterfaceComponent networkInterfaceComponent)
        {
            throw new NotImplementedException();
        }

        public override string Id { get; }
        public override string Name { get; }
        public override string Description { get; }
        public override OperationalStatus OperationalStatus { get; }
        public override long Speed { get; }
        public override bool IsReceiveOnly { get; }
        public override bool SupportsMulticast { get; }
        public override NetworkInterfaceType NetworkInterfaceType { get; }
    }

    [ExcludeFromCodeCoverage]
    internal sealed class TestablePcapPal : IPcapPal, IDisposable
    {
        private const int PCAP_ERROR = -1;

        private readonly NetworkInterface[] NetworkInterfaces =
        {
            new TestableNetworkInterface(NetworkInterfaceType.Loopback),
            new TestableNetworkInterface(NetworkInterfaceType.Ethernet)
        };
        private readonly byte[] DataWrittenAfterOpen = // npcap and winpcap
        {
            0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00
        };

        private bool _breakloop;
        private readonly ConcurrentBag<IntPtr> _memory;
        private int _nonblock;
        private byte _linkType;
        private int _snapshotLength;
        private int _readTimeout;
        private int _kernelBufferSize;
        private int _mintocopy;
        private ConcurrentQueue<Packet> _packetQueue;
        private uint _capturedPackets;
        private PacketCommunicatorMode _mode;
        private bool _winPcapBehavior;
        private GCHandle? _gcHandle;
        private GCHandle _samplingGcHandle;
        private PcapUnmanagedStructures.pcap_samp _sampling;
        private uint _sampleCounter;
        private DateTime _lastReceive;
        private string _lastError;
        private string _activeBpf;
        private Dictionary<IntPtr, string> _compiledBpfs;
        private FileStream _dumperFile;
        private long _acceptedBytes;

        private TestablePcapPal()
        {
            PcapHeaderSize = Marshal.SizeOf(typeof(PcapUnmanagedStructures.pcap_pkthdr_windows));
            _kernelBufferSize = 1_000_000;
            _mintocopy = 1_000_000;
            _memory = new ConcurrentBag<IntPtr>();
            _packetQueue = new ConcurrentQueue<Packet>();
            _samplingGcHandle = GCHandle.Alloc(_sampling, GCHandleType.Pinned);
            _lastError = "";
            _activeBpf = "";
            _compiledBpfs = new Dictionary<IntPtr, string>();
        }

        public static TestablePcapPal UseTestPal()
        {
            var pal = new TestablePcapPal();
            var pcapProperty = typeof(Interop).GetProperty(nameof(Interop.Pcap));
            pcapProperty.SetValue(null, pal, null);
            return pal;
        }

        public void SetWinPcapBehavior()
        {
            _winPcapBehavior = true;
        }

        public Encoding StringEncoding { get; }
        public int PcapHeaderSize { get; }
        public IntPtr CreatePcapPacketHeaderHandle(Packet packet)
        {
            var header = new PcapUnmanagedStructures.pcap_pkthdr_windows
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

        public unsafe PcapPacketHeader CreatePcapPacketHeader(IntPtr ptr)
        {
            var pcap_header = (PcapUnmanagedStructures.pcap_pkthdr_windows*)ptr;
            var timestamp = Interop.UnixEpoch.AddSeconds(pcap_header->ts.tv_sec).AddMicroseconds(pcap_header->ts.tv_usec).ToLocalTime();
            return new PcapPacketHeader(timestamp, pcap_header->caplen, pcap_header->len);
        }

        public PcapInterfaceHandle GetAllLocalMachine()
        {
            return new TestablePcapInterfaceHandle(_winPcapBehavior, NetworkInterfaces.First(n => n.NetworkInterfaceType == NetworkInterfaceType.Ethernet).Id);
        }

        public NetworkInterface[] GetAllNetworkInterfacesByDotNet()
        {
            return (NetworkInterface[])NetworkInterfaces.Clone();
        }


        public PacketTotalStatistics GetTotalStatistics(PcapHandle pcapDescriptor)
        {
            // needed for test SendAndReceivePacketTest
            var unixStatsType = typeof(PcapUnmanagedStructures).GetNestedType("pcap_stat_unix", BindingFlags.NonPublic);
            var justStatsToCreate = Activator.CreateInstance(unixStatsType);
            var totalStats = (PacketTotalStatistics)Activator.CreateInstance(typeof(PacketTotalStatistics), BindingFlags.NonPublic | BindingFlags.Instance, null, new object[] {justStatsToCreate}, null);
            var capturedField = typeof(PacketTotalStatistics).GetField("_packetsCaptured", BindingFlags.NonPublic | BindingFlags.Instance);
            capturedField.SetValue(totalStats, _capturedPackets);
            return totalStats;
        }

        public int pcap_findalldevs(ref PcapInterfaceHandle alldevs, out string errbuf)
        {
            throw new NotImplementedException();
        }

        public void pcap_freealldevs(IntPtr alldevs)
        {
        }

        public PcapHandle pcap_open(string dev, int packetLen, int flags, int read_timeout, ref PcapUnmanagedStructures.pcap_rmtauth rmtauth, out string errbuf)
        {
            _snapshotLength = packetLen;
            _readTimeout = read_timeout;
            errbuf = "";
            return new TestablePcapHandle();
        }

        public PcapHandle pcap_create(string dev, out string errbuf)
        {
            throw new NotImplementedException();
        }

        public unsafe PcapHandle pcap_open_offline(string fname, out string errbuf)
        {
            if (fname == "" || Path.GetInvalidFileNameChars().Any(Path.GetFileName(fname).Contains))
            {
                errbuf = $"{fname}: Invalid argument";
                return new PcapHandle();
            }
            errbuf = "";
            if (!File.Exists(fname))
                return new PcapHandle();

            var handle = new TestablePcapHandle(fname);
            // not sure whether this is the right place to read

            handle.FileDesc.Position = DataWrittenAfterOpen.Length;
            var headerBuffer = new byte[PcapHeaderSize];
            while (handle.FileDesc.CanRead)
            {
                var read = handle.FileDesc.Read(headerBuffer, 0, headerBuffer.Length);
                if (read < headerBuffer.Length)
                    break;

                PcapPacketHeader parsedHeader;
                fixed (byte* ptrHeader = headerBuffer)
                    parsedHeader = CreatePcapPacketHeader((IntPtr)ptrHeader);

                var buffer = new byte[parsedHeader.PacketLength];
                handle.FileDesc.Read(buffer, 0, buffer.Length);

                var packet = new Packet(buffer, parsedHeader.Timestamp, DataLinkKind.Ethernet, parsedHeader.OriginalLength);
                _packetQueue.Enqueue(packet);
            }
            return handle;
        }

        public PcapHandle pcap_open_dead(int linktype, int snaplen)
        {
            if ((_winPcapBehavior ? DataLinkPcapTypes_Winpcap : DataLinkPcapTypes_Npcap).TryGetValue(linktype, out var pcapType))
            {
                _linkType = pcapType;
                _snapshotLength = snaplen;
                return new TestablePcapHandle();
            }

            return new PcapHandle();
        }

        public IntPtr pcap_dump_open(PcapHandle adaptHandle, string fname)
        {
            _dumperFile = new FileStream(fname, FileMode.Create, FileAccess.ReadWrite, FileShare.Read);
            var header = (byte[])DataWrittenAfterOpen.Clone();
            header[20] = _linkType;
            _dumperFile.Write(header, 0, header.Length);

            return _dumperFile.Handle;
        }

        public long pcap_dump_ftell(IntPtr pcapDumper)
        {
            if (pcapDumper != _dumperFile?.Handle)
                throw new NotImplementedException();

            return _dumperFile.Position;
        }

        public void pcap_dump(IntPtr user, IntPtr header, IntPtr data)
        {
            if (user != _dumperFile?.Handle)
                throw new NotImplementedException();

            var parsedHeader = CreatePcapPacketHeader(header);
            var headerBuffer = new byte[PcapHeaderSize];
            Marshal.Copy(header, headerBuffer, 0, headerBuffer.Length);
            var buffer = new byte[parsedHeader.PacketLength];
            Marshal.Copy(data, buffer, 0, buffer.Length);

            _dumperFile.Write(headerBuffer, 0, headerBuffer.Length);
            _dumperFile.Write(buffer, 0, buffer.Length);
        }

        public void pcap_close(IntPtr adaptHandle)
        {
        }

        public int pcap_next_ex(PcapHandle adaptHandle, ref IntPtr header, ref IntPtr data)
        {
            if (!(adaptHandle is TestablePcapHandle handle))
                throw new NotSupportedException();

            if (_mode == PacketCommunicatorMode.Statistics)
            {
                if (_kernelBufferSize < sizeof(ulong) * 2)
                    return -1;
            }
            else
            {
                if (_kernelBufferSize < 576)
                    return -1;

                if (!handle.IsOffline && _packetQueue.Sum(x => x.Length + 12) < _mintocopy)
                    Thread.Sleep(_readTimeout);
            }

            if (!string.IsNullOrEmpty(_activeBpf))
            {
                var macs = CreateRegexMatch(_activeBpf);
                var src = new MacAddress(macs.Groups["src"].Value);
                var dst = new MacAddress(macs.Groups["dst"].Value);

                while (_packetQueue.TryPeek(out var filterablePacket))
                {
                    if (filterablePacket.Ethernet.Source == src && filterablePacket.Ethernet.Destination == dst)
                        break;
                    _packetQueue.TryDequeue(out _);
                }
            }

            if (_sampling.method == SamplingMethod.PCAP_SAMP_1_EVERY_N)
            {
                while (_packetQueue.Count > 0)
                {
                    _sampleCounter++;
                    if (_sampleCounter % _sampling.value == 0)
                    {
                        break;
                    }

                    _packetQueue.TryDequeue(out _);
                }
            }
            else if (_sampling.method == SamplingMethod.PCAP_SAMP_FIRST_AFTER_N_MS && SamplingInterval(handle.IsOffline))
            {
                return handle.IsOffline ? -2 : 0;
            }

            if (header == IntPtr.Zero)
            {
                _packetQueue.TryPeek(out var nextPacket);
                header = CreateHeaderFromDriverSide(nextPacket);
                _memory.Add(header);
            }
            else
            {
                throw new NotImplementedException();
            }

            // free because of ".. are not guaranteed to be valid after the next call to pcap_next_ex .." possible
            _gcHandle?.Free();
            byte[] rawData;
            bool gotPacket = false;
            if (_mode == PacketCommunicatorMode.Statistics)
            {
                _acceptedBytes += _packetQueue.IsEmpty ? 0 : _packetQueue.Sum(p => p.Length + 12);
                rawData = BitConverter.GetBytes((ulong)_packetQueue.Count).Concat(BitConverter.GetBytes(_acceptedBytes)).ToArray();
            }
            else
            {
                gotPacket = _packetQueue.TryDequeue(out var packet);
                rawData = gotPacket ? packet.Buffer.Take(_snapshotLength).ToArray() : new byte[0];
                _lastReceive = handle.IsOffline && gotPacket ? packet.Timestamp : DateTime.Now;
            }

            _gcHandle = GCHandle.Alloc(rawData, GCHandleType.Pinned);
            data = _gcHandle.Value.AddrOfPinnedObject();

            if (_mode == PacketCommunicatorMode.Capture && gotPacket)
                _capturedPackets++;
            if (handle.IsOffline)
                return gotPacket ? 1 : -2;
            return _mode == PacketCommunicatorMode.Statistics ? 1 : gotPacket ? 1 : 0;
        }

        private static Match CreateRegexMatch(string bpf)
        {
            return Regex.Match(bpf,
                "(?:ether src (?<src>[\\dA-F]{2}(:[\\dA-F]{2}){5}) and ether dst (?<dst>[\\dA-F]{2}(:[\\dA-F]{2}){5}))", RegexOptions.IgnoreCase);
        }

        private bool SamplingInterval(bool isOffline)
        {
            var readTimeout = _lastReceive.AddMilliseconds(_readTimeout);
            var ignoreBefore = _lastReceive.AddMilliseconds(_sampling.value);
            while (_packetQueue.TryPeek(out var tmpPacket) || ignoreBefore > DateTime.Now)
            {
                if (tmpPacket == null)
                {
                    if (isOffline || _lastReceive != DateTime.MinValue && readTimeout < DateTime.Now)
                        return true;

                    Thread.Sleep(100);
                }
                else if (_packetQueue.TryPeek(out var packet) && packet.Timestamp < ignoreBefore)
                    _packetQueue.TryDequeue(out _);
                else
                    break;
            }

            return false;
        }

        public int pcap_sendpacket(PcapHandle adaptHandle, IntPtr data, int size)
        {
            if (!(adaptHandle is TestablePcapHandle handle))
                throw new NotSupportedException();

            if (handle.IsOffline)
                return PCAP_ERROR;

            var managedArray = new byte[size];
            Marshal.Copy(data, managedArray, 0, size);
            _packetQueue.Enqueue(new Packet(managedArray, DateTime.Now, DataLinkKind.Ethernet));
            return 0;
        }

        public int pcap_compile(PcapHandle adaptHandle, IntPtr fp, string str, int optimize, uint netmask)
        {
            if (str.StartsWith("ether ")) {
                _compiledBpfs[fp] = str; // overwrite existing, because they are already freed
                return 0; // no reset of _lastError!
            }
            else
            {
                _lastError = "syntax error";
                return PCAP_ERROR;
            }
        }

        public int pcap_setfilter(PcapHandle adaptHandle, IntPtr fp)
        {
            if (_compiledBpfs.TryGetValue(fp, out var bpf))
            {
                _activeBpf = bpf;
                return 0;
            }
            return PCAP_ERROR;
        }

        public int pcap_offline_filter(IntPtr prog, IntPtr header, IntPtr pkt_data)
        {
            var packetHeader = Interop.Pcap.CreatePcapPacketHeader(header);
            var buffer = new byte[packetHeader.PacketLength];
            Marshal.Copy(pkt_data, buffer, 0, buffer.Length);

            var packet = new Packet(buffer, packetHeader.Timestamp, new PcapDataLink(DataLinkKind.Ethernet), packetHeader.OriginalLength);
            var macs = CreateRegexMatch(_compiledBpfs[prog]);
            var src = new MacAddress(macs.Groups["src"].Value);
            var dst = new MacAddress(macs.Groups["dst"].Value);

            if (packet.Ethernet.Source == src && packet.Ethernet.Destination == dst)
                return _snapshotLength;

            return 0;
        }

        public void pcap_freecode(IntPtr fp)
        {
            // allow setting filter to been able to test real and simulation
        }

        public string pcap_geterr(PcapHandle adaptHandle)
        {
            return _lastError;
        }

        public string pcap_lib_version()
        {
            throw new NotImplementedException();
        }

        public IntPtr pcap_dump_file(IntPtr p)
        {
            throw new NotImplementedException();
        }

        public int pcap_dump_flush(IntPtr p)
        {
            if (p != _dumperFile?.Handle)
                throw new NotImplementedException();

            _dumperFile.Flush();
            return 0;
        }

        public void pcap_dump_close(IntPtr p)
        {
            if (p != _dumperFile?.Handle)
                throw new NotImplementedException();

            _dumperFile.Close();
            _dumperFile = null;
        }

        public int pcap_datalink(PcapHandle adaptHandle)
        {
            if (adaptHandle.IsClosed)
                throw new ObjectDisposedException("SafeHandle was closed."); // necessary to simulate stop of infinite task
            return 1; // Ethernet
        }

        public int pcap_set_datalink(PcapHandle adaptHandle, int dlt)
        {
            return dlt > 0 ? 0 : 1; // see https://linux.die.net/man/7/pcap-linktype
        }

        public int pcap_list_datalinks(PcapHandle adaptHandle, ref IntPtr dataLinkList)
        {
            throw new NotImplementedException();
        }

        public void pcap_free_datalinks(IntPtr dataLinkList)
        {
            throw new NotImplementedException();
        }

        public int pcap_datalink_name_to_val(string name)
        {
            bool success;
            int ret;
            if (_winPcapBehavior)
            {
                success = Enum.TryParse(name, out DataLinkNamesWinpcap winpcap);
                ret = (int)winpcap;
            }
            else
            {
                success = Enum.TryParse(name, out DataLinkNamesNpcap npcap);
                ret = (int)npcap;
            }
            return success ? ret : PCAP_ERROR;
        }

        public string pcap_datalink_val_to_name(int dlt)
        {
            return Enum.GetName(_winPcapBehavior ? typeof(DataLinkNamesWinpcap) : typeof(DataLinkNamesNpcap), dlt); // returns null for unknown data link types
        }

        public string pcap_datalink_val_to_description(int dlt)
        {
            if ((_winPcapBehavior ? DataLinkDescriptionsWinpcap : DataLinkDescriptionsNpcap).TryGetValue(dlt, out var val))
                return val;

            return null; // returns null for unknown data link types
        }

        public string pcap_datalink_val_to_description_or_dlt(int dlt)
        {
            throw new NotImplementedException();
        }

        public int pcap_setnonblock(PcapHandle adaptHandle, int nonblock, out string errbuf)
        {
            if (!(adaptHandle is TestablePcapHandle handle))
                throw new NotSupportedException();

            errbuf = "";
            if (handle.IsOffline)
            {
                if (_winPcapBehavior)
                    return 0;

                errbuf = "Savefiles cannot be put into non-blocking mode";
                return PCAP_ERROR;
            }
            _nonblock = nonblock;
            return 0;
        }

        public int pcap_getnonblock(PcapHandle adaptHandle, out string errbuf)
        {
            errbuf = "";
            return _nonblock;
        }

        public int pcap_dispatch(PcapHandle adaptHandle, int count, PcapUnmanagedStructures.pcap_handler callback, IntPtr ptr, out bool breakloop)
        {
            if (!(adaptHandle is TestablePcapHandle testHandle))
                throw new NotSupportedException();

            try
            {
                breakloop = _breakloop;
                if (breakloop)
                {
                    return -2;
                }
                if (_mode == PacketCommunicatorMode.Statistics)
                {
                    if (_kernelBufferSize < sizeof(ulong) * 2)
                        return -1;
                }
                else
                {
                    if (_kernelBufferSize < 576)
                        return -1;
                }

                if (_sampling.method == SamplingMethod.PCAP_SAMP_1_EVERY_N)
                {
                    throw new NotImplementedException();
                    while (_packetQueue.Count > 0)
                    {
                        _sampleCounter++;
                        if (_sampleCounter % _sampling.value == 0)
                        {
                            break;
                        }

                        _packetQueue.TryDequeue(out _);
                    }
                }
                else if (_sampling.method == SamplingMethod.PCAP_SAMP_FIRST_AFTER_N_MS && SamplingInterval(testHandle.IsOffline))
                {
                    return 0; // not tested for offline
                }

                int ret = 0;
                while (count <= 0 ? _packetQueue.Count > 0 : ret < count)
                {
                    if (_breakloop)
                    {
                        breakloop = true;
                        return ret;
                    }

                    if (_packetQueue.TryDequeue(out var packet))
                    {
                        _lastReceive = DateTime.Now;

                        var header = CreatePcapPacketHeaderHandle(packet);
                        var cutData = packet.Buffer.Take(_snapshotLength).ToArray();
                        var handle = GCHandle.Alloc(cutData, GCHandleType.Pinned);
                        callback(IntPtr.Zero /* not used*/, header, handle.AddrOfPinnedObject());
                        handle.Free();
                        Marshal.FreeHGlobal(header);
                        ret++;
                    }
                    else
                        break;
                }

                if (!testHandle.IsOffline && ret == 0 && _nonblock == 0 && _sampling.method == SamplingMethod.PCAP_SAMP_NOSAMP)
                    Thread.Sleep(_readTimeout);

                if (_winPcapBehavior && testHandle.IsOffline)
                    return count > 0 && count <= ret ? ret : 0;
                else
                    return ret;
            }
            finally
            {
                _breakloop = false;
            }
        }

        public unsafe int pcap_loop(PcapHandle adaptHandle, int count, PcapUnmanagedStructures.pcap_handler callback, IntPtr ptr)
        {
            if (!(adaptHandle is TestablePcapHandle handle))
                throw new NotSupportedException();

            try
            {
                if (_breakloop)
                {
                    return -2;
                }
                if (_mode == PacketCommunicatorMode.Statistics)
                {
                    if (_kernelBufferSize < sizeof(ulong) * 2)
                        return -1;
                }
                else
                {
                    if (_kernelBufferSize < 576)
                        return -1;
                }

                if (_packetQueue.Count > 0)
                {
                    if (_mode == PacketCommunicatorMode.Statistics)
                        Thread.Sleep(_readTimeout); // https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut9.html

                    int ret = 0;
                    var condition = new Func<bool>(() => count > 0 ? ret < count : true);
                    while (condition())
                    {
                        if (_breakloop)
                        {
                            return -2;
                        }

                        if (_packetQueue.Count > 0 || _mode == PacketCommunicatorMode.Statistics)
                        {
                            Packet packet;
                            byte[] cutData;
                            if (_mode == PacketCommunicatorMode.Statistics)
                            {
                                cutData = BitConverter.GetBytes((ulong)_packetQueue.Count)
                                    .Concat(BitConverter.GetBytes((ulong)_packetQueue.Sum(x => x.Length + 12))).ToArray();
                                _packetQueue.TryDequeue(out packet);
                                while (_packetQueue.TryDequeue(out _));
                            }
                            else
                            {
                                _packetQueue.TryDequeue(out packet);
                                cutData = packet.Buffer.Take(_snapshotLength).ToArray();
                            }

                            var header = CreateHeaderFromDriverSide(packet);
                            var dataHandle = GCHandle.Alloc(cutData, GCHandleType.Pinned);
                            callback(IntPtr.Zero /* not used*/, header, dataHandle.AddrOfPinnedObject());
                            dataHandle.Free();
                            Marshal.FreeHGlobal(header);
                            ret++;
                        }

                        if (_breakloop)
                        {
                            return -2;
                        }

                        if (handle.IsOffline && _packetQueue.IsEmpty)
                            return 0;

                        if (condition() && _mode == PacketCommunicatorMode.Statistics)
                            Thread.Sleep(_readTimeout);
                    }

                    return _mode == PacketCommunicatorMode.Statistics ? 0 : ret;
                }

                return 0;
            }
            finally
            {
                _breakloop = false;
            }
        }

        private IntPtr CreateHeaderFromDriverSide(Packet packet)
        {
            // because of timestamp
            IntPtr header = CreatePcapPacketHeaderHandle(packet == null ? new Packet(new byte[16] /* nur sure why this size for statistic mode */, DateTime.Now, DataLinkKind.Ethernet) : new Packet(packet.Buffer, packet.Timestamp, DataLinkKind.Ethernet));

            if (packet != null)
                Marshal.WriteInt32(header + PcapHeaderSize - 8, Math.Min(packet.Length, _snapshotLength)); // necessary because of Math.Max in Packet ctor
            else if (_mode == PacketCommunicatorMode.Capture)
            {
                for (int i = 0; i < PcapHeaderSize; i++)
                    Marshal.WriteByte(header + i, 0);
            }

            return header;
        }

        public int pcap_breakloop(PcapHandle p)
        {
            _breakloop = true;
            return 0;
        }

        public int pcap_get_selectable_fd(PcapHandle adaptHandle)
        {
            throw new NotImplementedException();
        }

        public int pcap_stats(PcapHandle adapter, IntPtr stat)
        {
            throw new NotImplementedException();
        }

        public int pcap_snapshot(PcapHandle adapter)
        {
            throw new NotImplementedException();
        }

        public int pcap_is_swapped(PcapHandle adapter)
        {
            throw new NotImplementedException();
        }

        public int pcap_major_version(PcapHandle adapter)
        {
            throw new NotImplementedException();
        }

        public int pcap_minor_version(PcapHandle adapter)
        {
            throw new NotImplementedException();
        }

        public int pcap_set_rfmon(PcapHandle p, int rfmon)
        {
            throw new NotImplementedException();
        }

        public int pcap_set_snaplen(PcapHandle p, int snaplen)
        {
            throw new NotImplementedException();
        }

        public int pcap_set_promisc(PcapHandle p, int promisc)
        {
            throw new NotImplementedException();
        }

        public int pcap_set_timeout(PcapHandle p, int to_ms)
        {
            throw new NotImplementedException();
        }

        public int pcap_activate(PcapHandle p)
        {
            throw new NotImplementedException();
        }

        public int pcap_fileno(PcapHandle adapter)
        {
            throw new NotImplementedException();
        }

        public int pcap_setmode(PcapHandle adapter, PacketCommunicatorMode mode)
        {
            if (!(adapter is TestablePcapHandle handle))
                throw new NotSupportedException();

            if (handle.IsOffline || !Enum.IsDefined(typeof(PacketCommunicatorMode), mode))
                return PCAP_ERROR;

            _mode = mode;
            return 0;
        }

        public int pcap_setbuff(PcapHandle adapter, int dim)
        {
            if (!(adapter is TestablePcapHandle handle))
                throw new NotSupportedException();

            if (handle.IsOffline)
                return PCAP_ERROR;

            _kernelBufferSize = dim;
            return 0;
        }

        public int pcap_setmintocopy(PcapHandle adapter, int size)
        {
            if (!(adapter is TestablePcapHandle handle))
                throw new NotSupportedException();

            if (handle.IsOffline)
                return PCAP_ERROR;

            _mintocopy = size;
            return 0;
        }

        public unsafe IntPtr pcap_setsampling(PcapHandle adapter)
        {
            fixed (PcapUnmanagedStructures.pcap_samp* f = &_sampling)
                return (IntPtr)f;
        }

        public int pcap_sendqueue_transmit(PcapHandle p, ref PcapUnmanagedStructures.pcap_send_queue queue, int sync)
        {
            int pos = 0;
            while (pos < queue.len)
            {
                var header = CreatePcapPacketHeader(queue.ptrBuff + pos);
                var fullPacket = new byte[header.PacketLength];
                Marshal.Copy(queue.ptrBuff + pos + PcapHeaderSize, fullPacket, 0, fullPacket.Length);
                _packetQueue.Enqueue(new Packet(fullPacket, sync != 0 ? header.Timestamp : DateTime.Now, DataLinkKind.Ethernet, header.OriginalLength));

                pos += PcapHeaderSize + fullPacket.Length;
            }

            return pos;
        }

        public void Dispose()
        {
            _gcHandle?.Free();
            _samplingGcHandle.Free();
            foreach (var ptr in _memory)
            {
                Marshal.FreeHGlobal(ptr);
            }
            _dumperFile?.Dispose();
        }

        public enum DataLinkNamesWinpcap
        {
            NULL = 0,
            EN10MB = 1,
            IEEE802 = 6,
            ARCNET = 7,
            SLIP = 8,
            PPP = 9,
            FDDI = 10,
            ATM_RFC1483 = 11,
            RAW = 12,
            SLIP_BSDOS = 15,
            PPP_BSDOS = 16,
            ATM_CLIP = 19,
            PPP_SERIAL = 50,
            PPP_ETHER = 51,
            SYMANTEC_FIREWALL = 99,
            C_HDLC = 104,
            IEEE802_11 = 105,
            FRELAY = 107,
            LOOP = 108,
            ENC = 109,
            LINUX_SLL = 113,
            LTALK = 114,
            PFLOG = 117,
            PRISM_HEADER = 119,
            IP_OVER_FC = 122,
            SUNATM = 123,
            IEEE802_11_RADIO = 127,
            ARCNET_LINUX = 129,
            JUNIPER_MLPPP = 130,
            JUNIPER_MLFR = 131,
            JUNIPER_ES = 132,
            JUNIPER_GGSN = 133,
            JUNIPER_MFR = 134,
            JUNIPER_ATM2 = 135,
            JUNIPER_SERVICES = 136,
            JUNIPER_ATM1 = 137,
            APPLE_IP_OVER_IEEE1394 = 138,
            MTP2_WITH_PHDR = 139,
            MTP2 = 140,
            MTP3 = 141,
            SCCP = 142,
            DOCSIS = 143,
            LINUX_IRDA = 144,
            IEEE802_11_RADIO_AVS = 163,
            JUNIPER_MONITOR = 164,
            PPP_PPPD = 166,
            JUNIPER_PPPOE = 167,
            JUNIPER_PPPOE_ATM = 168,
            GPRS_LLC = 169,
            GPF_T = 170,
            GPF_F = 171,
            JUNIPER_PIC_PEER = 174,
            ERF_ETH = 175,
            ERF_POS = 176,
            LINUX_LAPD = 177,
            JUNIPER_ETHER = 178,
            JUNIPER_PPP = 179,
            JUNIPER_FRELAY = 180,
            JUNIPER_CHDLC = 181,
            MFR = 182,
            JUNIPER_VP = 183,
            A429 = 184,
            A653_ICM = 185,
            USB = 186,
            BLUETOOTH_HCI_H4 = 187,
            IEEE802_16_MAC_CPS = 188,
            USB_LINUX = 189,
            CAN20B = 190,
            IEEE802_15_4_LINUX = 191,
            PPI = 192,
            IEEE802_16_MAC_CPS_RADIO = 193,
            JUNIPER_ISM = 194,
            IEEE802_15_4 = 195,
            SITA = 196,
            ERF = 197,
            RAIF1 = 198,
            IPMB = 199,
            JUNIPER_ST = 200,
            BLUETOOTH_HCI_H4_WITH_PHDR = 201,
            AX25_KISS = 202,
            PPP_WITH_DIR = 204,
            IEEE802_15_4_NONASK_PHY = 215,
        }

        public enum DataLinkNamesNpcap
        {
            NULL = 0,
            EN10MB = 1,
            IEEE802 = 6,
            ARCNET = 7,
            SLIP = 8,
            PPP = 9,
            FDDI = 10,
            ATM_RFC1483 = 11,
            RAW = 12,
            SLIP_BSDOS = 15,
            PPP_BSDOS = 16,
            ATM_CLIP = 19,
            PPP_SERIAL = 50,
            PPP_ETHER = 51,
            SYMANTEC_FIREWALL = 99,
            C_HDLC = 104,
            IEEE802_11 = 105,
            FRELAY = 107,
            LOOP = 108,
            ENC = 109,
            LINUX_SLL = 113,
            LTALK = 114,
            PFLOG = 117,
            PRISM_HEADER = 119,
            IP_OVER_FC = 122,
            SUNATM = 123,
            IEEE802_11_RADIO = 127,
            ARCNET_LINUX = 129,
            JUNIPER_MLPPP = 130,
            JUNIPER_MLFR = 131,
            JUNIPER_ES = 132,
            JUNIPER_GGSN = 133,
            JUNIPER_MFR = 134,
            JUNIPER_ATM2 = 135,
            JUNIPER_SERVICES = 136,
            JUNIPER_ATM1 = 137,
            APPLE_IP_OVER_IEEE1394 = 138,
            MTP2_WITH_PHDR = 139,
            MTP2 = 140,
            MTP3 = 141,
            SCCP = 142,
            DOCSIS = 143,
            LINUX_IRDA = 144,
            IEEE802_11_RADIO_AVS = 163,
            JUNIPER_MONITOR = 164,
            BACNET_MS_TP = 165,
            PPP_PPPD = 166,
            JUNIPER_PPPOE = 167,
            JUNIPER_PPPOE_ATM = 168,
            GPRS_LLC = 169,
            GPF_T = 170,
            GPF_F = 171,
            JUNIPER_PIC_PEER = 174,
            ERF_ETH = 175,
            ERF_POS = 176,
            LINUX_LAPD = 177,
            JUNIPER_ETHER = 178,
            JUNIPER_PPP = 179,
            JUNIPER_FRELAY = 180,
            JUNIPER_CHDLC = 181,
            MFR = 182,
            JUNIPER_VP = 183,
            A429 = 184,
            A653_ICM = 185,
            USB_FREEBSD = 186,
            BLUETOOTH_HCI_H4 = 187,
            IEEE802_16_MAC_CPS = 188,
            USB_LINUX = 189,
            CAN20B = 190,
            IEEE802_15_4_LINUX = 191,
            PPI = 192,
            IEEE802_16_MAC_CPS_RADIO = 193,
            JUNIPER_ISM = 194,
            IEEE802_15_4 = 195,
            SITA = 196,
            ERF = 197,
            RAIF1 = 198,
            IPMB_KONTRON = 199,
            JUNIPER_ST = 200,
            BLUETOOTH_HCI_H4_WITH_PHDR = 201,
            AX25_KISS = 202,
            PPP_WITH_DIR = 204,
            IPMB_LINUX = 209,
            IEEE802_15_4_NONASK_PHY = 215,
            LINUX_EVDEV = 216,
            MPLS = 219,
            USB_LINUX_MMAPPED = 220,
            DECT = 221,
            AOS = 222,
            WIHART = 223,
            FC_2 = 224,
            FC_2_WITH_FRAME_DELIMS = 225,
            IPNET = 226,
            CAN_SOCKETCAN = 227,
            IPV4 = 228,
            IPV6 = 229,
            IEEE802_15_4_NOFCS = 230,
            DBUS = 231,
            JUNIPER_VS = 232,
            JUNIPER_SRX_E2E = 233,
            JUNIPER_FIBRECHANNEL = 234,
            DVB_CI = 235,
            MUX27010 = 236,
            STANAG_5066_D_PDU = 237,
            JUNIPER_ATM_CEMIC = 238,
            NFLOG = 239,
            NETANALYZER = 240,
            NETANALYZER_TRANSPARENT = 241,
            IPOIB = 242,
            MPEG_2_TS = 243,
            NG40 = 244,
            NFC_LLCP = 245,
            PFSYNC = 246,
            INFINIBAND = 247,
            SCTP = 248,
            USBPCAP = 249,
            RTAC_SERIAL = 250,
            BLUETOOTH_LE_LL = 251,
            NETLINK = 253,
            BLUETOOTH_LINUX_MONITOR = 254,
            BLUETOOTH_BREDR_BB = 255,
            BLUETOOTH_LE_LL_WITH_PHDR = 256,
            PROFIBUS_DL = 257,
            PKTAP = 258,
            EPON = 259,
            IPMI_HPM_2 = 260,
            ZWAVE_R1_R2 = 261,
            ZWAVE_R3 = 262,
            WATTSTOPPER_DLM = 263,
            ISO_14443 = 264,
            RDS = 265,
            USB_DARWIN = 266,
            OPENFLOW = 267,
            SDLC = 268,
            TI_LLN_SNIFFER = 269,
            VSOCK = 271,
            NORDIC_BLE = 272,
            DOCSIS31_XRA31 = 273,
            ETHERNET_MPACKET = 274,
            DISPLAYPORT_AUX = 275,
            LINUX_SLL2 = 276,
            OPENVIZSLA = 278,
            EBHSCR = 279,
            VPP_DISPATCH = 280,
            DSA_TAG_BRCM = 281,
            DSA_TAG_BRCM_PREPEND = 282,
            IEEE802_15_4_TAP = 283,
            DSA_TAG_DSA = 284,
            DSA_TAG_EDSA = 285,
            ELEE = 286,
            Z_WAVE_SERIAL = 287,
            USB_2_0 = 288,
            ATSC_ALP = 289,
        }

        public static Dictionary<int, string> DataLinkDescriptionsWinpcap = new Dictionary<int, string>()
        {
            { 0, "BSD loopback" },
            { 1, "Ethernet" },
            { 6, "Token ring" },
            { 7, "BSD ARCNET" },
            { 8, "SLIP" },
            { 9, "PPP" },
            { 10, "FDDI" },
            { 11, "RFC 1483 LLC-encapsulated ATM" },
            { 12, "Raw IP" },
            { 15, "BSD/OS SLIP" },
            { 16, "BSD/OS PPP" },
            { 19, "Linux Classical IP-over-ATM" },
            { 50, "PPP over serial" },
            { 51, "PPPoE" },
            { 99, "Symantec Firewall" },
            { 104, "Cisco HDLC" },
            { 105, "802.11" },
            { 107, "Frame Relay" },
            { 108, "OpenBSD loopback" },
            { 109, "OpenBSD encapsulated IP" },
            { 113, "Linux cooked" },
            { 114, "Localtalk" },
            { 117, "OpenBSD pflog file" },
            { 119, "802.11 plus Prism header" },
            { 122, "RFC 2625 IP-over-Fibre Channel" },
            { 123, "Sun raw ATM" },
            { 127, "802.11 plus radiotap header" },
            { 129, "Linux ARCNET" },
            { 130, "Juniper Multi-Link PPP" },
            { 131, "Juniper Multi-Link Frame Relay" },
            { 132, "Juniper Encryption Services PIC" },
            { 133, "Juniper GGSN PIC" },
            { 134, "Juniper FRF.16 Frame Relay" },
            { 135, "Juniper ATM2 PIC" },
            { 136, "Juniper Advanced Services PIC" },
            { 137, "Juniper ATM1 PIC" },
            { 138, "Apple IP-over-IEEE 1394" },
            { 139, "SS7 MTP2 with Pseudo-header" },
            { 140, "SS7 MTP2" },
            { 141, "SS7 MTP3" },
            { 142, "SS7 SCCP" },
            { 143, "DOCSIS" },
            { 144, "Linux IrDA" },
            { 163, "802.11 plus AVS radio information header" },
            { 164, "Juniper Passive Monitor PIC" },
            { 166, "PPP for pppd, with direction flag" },
            { 167, "Juniper PPPoE" },
            { 168, "Juniper PPPoE/ATM" },
            { 169, "GPRS LLC" },
            { 170, "GPF-T" },
            { 171, "GPF-F" },
            { 174, "Juniper PIC Peer" },
            { 175, "Ethernet with Endace ERF header" },
            { 176, "Packet-over-SONET with Endace ERF header" },
            { 177, "Linux vISDN LAPD" },
            { 178, "Juniper Ethernet" },
            { 179, "Juniper PPP" },
            { 180, "Juniper Frame Relay" },
            { 181, "Juniper C-HDLC" },
            { 182, "FRF.16 Frame Relay" },
            { 183, "Juniper Voice PIC" },
            { 184, "Arinc 429" },
            { 185, "Arinc 653 Interpartition Communication" },
            { 186, "USB" },
            { 187, "Bluetooth HCI UART transport layer" },
            { 188, "IEEE 802.16 MAC Common Part Sublayer" },
            { 189, "USB with Linux header" },
            { 190, "Controller Area Network (CAN) v. 2.0B" },
            { 191, "IEEE 802.15.4 with Linux padding" },
            { 192, "Per-Packet Information" },
            { 193, "IEEE 802.16 MAC Common Part Sublayer plus radiotap header" },
            { 194, "Juniper Integrated Service Module" },
            { 195, "IEEE 802.15.4" },
            { 196, "SITA pseudo-header" },
            { 197, "Endace ERF header" },
            { 198, "Ethernet with u10 Networks pseudo-header" },
            { 199, "IPMB" },
            { 200, "Juniper Secure Tunnel" },
            { 201, "Bluetooth HCI UART transport layer plus pseudo-header" },
            { 202, "AX.25 with KISS header" },
            { 204, "PPP with Directional Info" },
            { 215, "IEEE 802.15.4 with non-ASK PHY data" },
        };

        public static Dictionary<int, string> DataLinkDescriptionsNpcap = new Dictionary<int, string>()
        {
            { 0, "BSD loopback" },
            { 1, "Ethernet" },
            { 6, "Token ring" },
            { 7, "BSD ARCNET" },
            { 8, "SLIP" },
            { 9, "PPP" },
            { 10, "FDDI" },
            { 11, "RFC 1483 LLC-encapsulated ATM" },
            { 12, "Raw IP" },
            { 15, "BSD/OS SLIP" },
            { 16, "BSD/OS PPP" },
            { 19, "Linux Classical IP over ATM" },
            { 50, "PPP over serial" },
            { 51, "PPPoE" },
            { 99, "Symantec Firewall" },
            { 104, "Cisco HDLC" },
            { 105, "802.11" },
            { 107, "Frame Relay" },
            { 108, "OpenBSD loopback" },
            { 109, "OpenBSD encapsulated IP" },
            { 113, "Linux cooked v1" },
            { 114, "Localtalk" },
            { 117, "OpenBSD pflog file" },
            { 119, "802.11 plus Prism header" },
            { 122, "RFC 2625 IP-over-Fibre Channel" },
            { 123, "Sun raw ATM" },
            { 127, "802.11 plus radiotap header" },
            { 129, "Linux ARCNET" },
            { 130, "Juniper Multi-Link PPP" },
            { 131, "Juniper Multi-Link Frame Relay" },
            { 132, "Juniper Encryption Services PIC" },
            { 133, "Juniper GGSN PIC" },
            { 134, "Juniper FRF.16 Frame Relay" },
            { 135, "Juniper ATM2 PIC" },
            { 136, "Juniper Advanced Services PIC" },
            { 137, "Juniper ATM1 PIC" },
            { 138, "Apple IP-over-IEEE 1394" },
            { 139, "SS7 MTP2 with Pseudo-header" },
            { 140, "SS7 MTP2" },
            { 141, "SS7 MTP3" },
            { 142, "SS7 SCCP" },
            { 143, "DOCSIS" },
            { 144, "Linux IrDA" },
            { 163, "802.11 plus AVS radio information header" },
            { 164, "Juniper Passive Monitor PIC" },
            { 165, "BACnet MS/TP" },
            { 166, "PPP for pppd, with direction flag" },
            { 167, "Juniper PPPoE" },
            { 168, "Juniper PPPoE/ATM" },
            { 169, "GPRS LLC" },
            { 170, "GPF-T" },
            { 171, "GPF-F" },
            { 174, "Juniper PIC Peer" },
            { 175, "Ethernet with Endace ERF header" },
            { 176, "Packet-over-SONET with Endace ERF header" },
            { 177, "Linux vISDN LAPD" },
            { 178, "Juniper Ethernet" },
            { 179, "Juniper PPP" },
            { 180, "Juniper Frame Relay" },
            { 181, "Juniper C-HDLC" },
            { 182, "FRF.16 Frame Relay" },
            { 183, "Juniper Voice PIC" },
            { 184, "Arinc 429" },
            { 185, "Arinc 653 Interpartition Communication" },
            { 186, "USB with FreeBSD header" },
            { 187, "Bluetooth HCI UART transport layer" },
            { 188, "IEEE 802.16 MAC Common Part Sublayer" },
            { 189, "USB with Linux header" },
            { 190, "Controller Area Network (CAN) v. 2.0B" },
            { 191, "IEEE 802.15.4 with Linux padding" },
            { 192, "Per-Packet Information" },
            { 193, "IEEE 802.16 MAC Common Part Sublayer plus radiotap header" },
            { 194, "Juniper Integrated Service Module" },
            { 195, "IEEE 802.15.4 with FCS" },
            { 196, "SITA pseudo-header" },
            { 197, "Endace ERF header" },
            { 198, "Ethernet with u10 Networks pseudo-header" },
            { 199, "IPMB with Kontron pseudo-header" },
            { 200, "Juniper Secure Tunnel" },
            { 201, "Bluetooth HCI UART transport layer plus pseudo-header" },
            { 202, "AX.25 with KISS header" },
            { 204, "PPP with Directional Info" },
            { 209, "IPMB with Linux/Pigeon Point pseudo-header" },
            { 215, "IEEE 802.15.4 with non-ASK PHY data" },
            { 216, "Linux evdev events" },
            { 219, "MPLS with label as link-layer header" },
            { 220, "USB with padded Linux header" },
            { 221, "DECT" },
            { 222, "AOS Space Data Link protocol" },
            { 223, "Wireless HART" },
            { 224, "Fibre Channel FC-2" },
            { 225, "Fibre Channel FC-2 with frame delimiters" },
            { 226, "Solaris ipnet" },
            { 227, "CAN-bus with SocketCAN headers" },
            { 228, "Raw IPv4" },
            { 229, "Raw IPv6" },
            { 230, "IEEE 802.15.4 without FCS" },
            { 231, "D-Bus" },
            { 232, "Juniper Virtual Server" },
            { 233, "Juniper SRX E2E" },
            { 234, "Juniper Fibre Channel" },
            { 235, "DVB-CI" },
            { 236, "MUX27010" },
            { 237, "STANAG 5066 D_PDUs" },
            { 238, "Juniper ATM CEMIC" },
            { 239, "Linux netfilter log messages" },
            { 240, "Ethernet with Hilscher netANALYZER pseudo-header" },
            { 241, "Ethernet with Hilscher netANALYZER pseudo-header and with preamble and SFD" },
            { 242, "RFC 4391 IP-over-Infiniband" },
            { 243, "MPEG-2 transport stream" },
            { 244, "ng40 protocol tester Iub/Iur" },
            { 245, "NFC LLCP PDUs with pseudo-header" },
            { 246, "Packet filter state syncing" },
            { 247, "InfiniBand" },
            { 248, "SCTP" },
            { 249, "USB with USBPcap header" },
            { 250, "Schweitzer Engineering Laboratories RTAC packets" },
            { 251, "Bluetooth Low Energy air interface" },
            { 253, "Linux netlink" },
            { 254, "Bluetooth Linux Monitor" },
            { 255, "Bluetooth Basic Rate/Enhanced Data Rate baseband packets" },
            { 256, "Bluetooth Low Energy air interface with pseudo-header" },
            { 257, "PROFIBUS data link layer" },
            { 258, "Apple DLT_PKTAP" },
            { 259, "Ethernet with 802.3 Clause 65 EPON preamble" },
            { 260, "IPMI trace packets" },
            { 261, "Z-Wave RF profile R1 and R2 packets" },
            { 262, "Z-Wave RF profile R3 packets" },
            { 263, "WattStopper Digital Lighting Management (DLM) and Legrand Nitoo Open protocol" },
            { 264, "ISO 14443 messages" },
            { 265, "IEC 62106 Radio Data System groups" },
            { 266, "USB with Darwin header" },
            { 267, "OpenBSD DLT_OPENFLOW" },
            { 268, "IBM SDLC frames" },
            { 269, "TI LLN sniffer frames" },
            { 271, "Linux vsock" },
            { 272, "Nordic Semiconductor Bluetooth LE sniffer frames" },
            { 273, "Excentis XRA-31 DOCSIS 3.1 RF sniffer frames" },
            { 274, "802.3br mPackets" },
            { 275, "DisplayPort AUX channel monitoring data" },
            { 276, "Linux cooked v2" },
            { 278, "OpenVizsla USB" },
            { 279, "Elektrobit High Speed Capture and Replay (EBHSCR)" },
            { 280, "VPP graph dispatch tracer" },
            { 281, "Broadcom tag" },
            { 282, "Broadcom tag (prepended)" },
            { 283, "IEEE 802.15.4 with pseudo-header" },
            { 284, "Marvell DSA" },
            { 285, "Marvell EDSA" },
            { 286, "ELEE lawful intercept packets" },
            { 287, "Z-Wave serial frames between host and chip" },
            { 288, "USB 2.0/1.1/1.0 as transmitted over the cable" },
            { 289, "ATSC Link-Layer Protocol packets" },
        };

        public static Dictionary<int, byte> DataLinkPcapTypes_Winpcap = new Dictionary<int, byte>()
        {
            { 0, 0x00 },
            { 1, 0x01 },
            { 6, 0x06 },
            { 7, 0x07 },
            { 8, 0x08 },
            { 9, 0x09 },
            { 10, 0x0A },
            { 11, 0x64 },
            { 12, 0x65 },
            { 15, 0x66 },
            { 16, 0x67 },
            { 19, 0x6A },
            { 50, 0x32 },
            { 51, 0x33 },
            { 99, 0x63 },
            { 104, 0x68 },
            { 105, 0x69 },
            { 107, 0x6B },
            { 108, 0x6C },
            { 113, 0x71 },
            { 114, 0x72 },
            { 117, 0x75 },
            { 119, 0x77 },
            { 122, 0x7A },
            { 123, 0x7B },
            { 127, 0x7F },
            { 129, 0x81 },
            { 130, 0x82 },
            { 131, 0x83 },
            { 132, 0x84 },
            { 133, 0x85 },
            { 134, 0x86 },
            { 135, 0x87 },
            { 136, 0x88 },
            { 137, 0x89 },
            { 138, 0x8A },
            { 139, 0x8B },
            { 140, 0x8C },
            { 141, 0x8D },
            { 142, 0x8E },
            { 143, 0x8F },
            { 144, 0x90 },
            { 163, 0xA3 },
            { 164, 0xA4 },
            { 165, 0xA5 },
            { 166, 0xA6 },
            { 167, 0xA7 },
            { 168, 0xA8 },
            { 169, 0xA9 },
            { 170, 0xAA },
            { 171, 0xAB },
            { 174, 0xAE },
            { 175, 0xAF },
            { 176, 0xB0 },
            { 177, 0xB1 },
            { 178, 0xB2 },
            { 179, 0xB3 },
            { 180, 0xB4 },
            { 181, 0xB5 },
            { 182, 0xB6 },
            { 183, 0xB7 },
            { 184, 0xB8 },
            { 185, 0xB9 },
            { 186, 0xBA },
            { 187, 0xBB },
            { 188, 0xBC },
            { 189, 0xBD },
            { 190, 0xBE },
            { 191, 0xBF },
            { 192, 0xC0 },
            { 193, 0xC1 },
            { 194, 0xC2 },
            { 195, 0xC3 },
            { 196, 0xC4 },
            { 197, 0xC5 },
            { 198, 0xC6 },
            { 199, 0xC7 },
            { 200, 0xC8 },
            { 201, 0xC9 },
            { 202, 0xCA },
            { 204, 0xCC },
            { 209, 0xD1 },
            { 215, 0xD7 },
        };

        public static Dictionary<int, byte> DataLinkPcapTypes_Npcap = new Dictionary<int, byte>()
        {
            { 0, 0x00 },
            { 1, 0x01 },
            { 6, 0x06 },
            { 7, 0x07 },
            { 8, 0x08 },
            { 9, 0x09 },
            { 10, 0x0A },
            { 11, 0x64 },
            { 12, 0x65 },
            { 15, 0x66 },
            { 16, 0x67 },
            { 19, 0x6A },
            { 50, 0x32 },
            { 51, 0x33 },
            { 99, 0x63 },
            { 104, 0x68 },
            { 105, 0x69 },
            { 107, 0x6B },
            { 108, 0x6C },
            { 113, 0x71 },
            { 114, 0x72 },
            { 117, 0x75 },
            { 119, 0x77 },
            { 122, 0x7A },
            { 123, 0x7B },
            { 127, 0x7F },
            { 129, 0x81 },
            { 130, 0x82 },
            { 131, 0x83 },
            { 132, 0x84 },
            { 133, 0x85 },
            { 134, 0x86 },
            { 135, 0x87 },
            { 136, 0x88 },
            { 137, 0x89 },
            { 138, 0x8A },
            { 139, 0x8B },
            { 140, 0x8C },
            { 141, 0x8D },
            { 142, 0x8E },
            { 143, 0x8F },
            { 144, 0x90 },
            { 163, 0xA3 },
            { 164, 0xA4 },
            { 165, 0xA5 },
            { 166, 0xA6 },
            { 167, 0xA7 },
            { 168, 0xA8 },
            { 169, 0xA9 },
            { 170, 0xAA },
            { 171, 0xAB },
            { 174, 0xAE },
            { 175, 0xAF },
            { 176, 0xB0 },
            { 177, 0xB1 },
            { 178, 0xB2 },
            { 179, 0xB3 },
            { 180, 0xB4 },
            { 181, 0xB5 },
            { 182, 0xB6 },
            { 183, 0xB7 },
            { 184, 0xB8 },
            { 185, 0xB9 },
            { 186, 0xBA },
            { 187, 0xBB },
            { 188, 0xBC },
            { 189, 0xBD },
            { 190, 0xBE },
            { 191, 0xBF },
            { 192, 0xC0 },
            { 193, 0xC1 },
            { 194, 0xC2 },
            { 195, 0xC3 },
            { 196, 0xC4 },
            { 197, 0xC5 },
            { 198, 0xC6 },
            { 199, 0xC7 },
            { 200, 0xC8 },
            { 201, 0xC9 },
            { 202, 0xCA },
            { 204, 0xCC },
            { 209, 0xD1 },
            { 215, 0xD7 },
            { 222, 0xDE },
            { 223, 0xDF },
            { 224, 0xE0 },
            { 225, 0xE1 },
            { 226, 0xE2 },
            { 227, 0xE3 },
            { 228, 0xE4 },
            { 229, 0xE5 },
            { 230, 0xE6 },
            { 231, 0xE7 },
            { 232, 0xE8 },
            { 233, 0xE9 },
            { 234, 0xEA },
            { 235, 0xEB },
            { 236, 0xEC },
            { 237, 0xED },
            { 238, 0xEE },
            { 239, 0xEF },
            { 240, 0xF0 },
            { 241, 0xF1 },
            { 242, 0xF2 },
            { 243, 0xF3 },
            { 244, 0xF4 },
            { 245, 0xF5 },
            { 246, 0xF6 },
            { 247, 0xF7 },
            { 248, 0xF8 },
            { 249, 0xF9 },
            { 250, 0xFA },
            { 251, 0xFB },
            { 253, 0xFD },
            { 254, 0xFE },
            { 255, 0xFF },
            { 256, 0x00 },
            { 257, 0x01 },
            { 258, 0x02 },
            { 259, 0x03 },
            { 260, 0x04 },
            { 261, 0x05 },
            { 262, 0x06 },
            { 263, 0x07 },
            { 264, 0x08 },
            { 265, 0x09 },
            { 266, 0x0A },
            { 267, 0x0B },
            { 268, 0x0C },
            { 269, 0x0D },
            { 271, 0x0F },
            { 272, 0x10 },
            { 273, 0x11 },
            { 274, 0x12 },
            { 275, 0x13 },
            { 276, 0x14 },
            { 278, 0x16 },
            { 279, 0x17 },
            { 280, 0x18 },
            { 281, 0x19 },
            { 282, 0x1A },
            { 283, 0x1B },
            { 284, 0x1C },
            { 285, 0x1D },
            { 286, 0x1E },
            { 287, 0x1F },
            { 288, 0x20 },
            { 289, 0x21 },
        };
    }
}
