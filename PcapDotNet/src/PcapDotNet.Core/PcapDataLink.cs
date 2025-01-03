using System;
using System.Globalization;
using System.Runtime.CompilerServices;
using PcapDotNet.Core.Native;
using PcapDotNet.Packets;

namespace PcapDotNet.Core
{
    /// <summary>
    /// A packet communicator datalink.
    /// </summary>
    public struct PcapDataLink : IDataLink, IEquatable<PcapDataLink>
    {
        private const int DLT_PPP_WITH_DIR = 204;

        private readonly int _value;

        /// <summary>
        /// Create the datalink from one of the well defined datalink kinds.
        /// </summary>
        /// <param name="kind">The kind of datalink to create.</param>
        public PcapDataLink(DataLinkKind kind)
        {
            _value = KindToValue(kind);
        }

        /// <summary>
        /// Create the datalink from an int value (pcap value).
        /// </summary>
        /// <param name="value">The pcap value of the datalink.</param>
        public PcapDataLink(int value)
        {
            _value = value;
        }

        /// <summary>
        /// Create the datalink its name.
        /// </summary>
        /// <param name="name">The name of the pcap datalink.</param>
        public PcapDataLink(string name)
        {
            var value = Interop.Pcap.pcap_datalink_name_to_val(name);
            if (value != -1)
            {
                _value = value;
                return;
            }

            if (name == "PPP_WITH_DIR")
            {
                _value = 204;
                return;
            }

            throw new ArgumentException("Invalid datalink name " + name, "name");
        }

        /// <summary>
        /// The kind of the datalink.
        /// </summary>
        public DataLinkKind Kind
        {
            [System.Security.SecurityCritical]
            get
            {
                switch (Name)
                {
                    case "EN10MB":
                        return DataLinkKind.Ethernet;

                    case "RAW":
                        return DataLinkKind.IpV4;

                    case "DOCSIS":
                        return DataLinkKind.Docsis;

                    case "PPP_WITH_DIR":
                        return DataLinkKind.PointToPointProtocolWithDirection;

                    case "LINUX_SLL":
                        return DataLinkKind.LinuxSll;

                    default:
                        throw new NotSupportedException("PcapDataLink " + Value.ToString(CultureInfo.InvariantCulture) + " - " + ToString() + " is unsupported");
                }
            }
        }

        /// <summary>
        /// The pcap value of the datalink.
        /// </summary>
        public int Value => _value;

        /// <summary>
        /// The name of the datalink.
        /// </summary>
        public string Name
        {
            get
            {
                var name = Interop.Pcap.pcap_datalink_val_to_name(Value);
                if (!string.IsNullOrEmpty(name))
                    return name;

                switch (Value)
                {
                    case DLT_PPP_WITH_DIR:
                        return "PPP_WITH_DIR";

                    default:
                        throw new InvalidOperationException("PcapDataLink " + Value.ToString(CultureInfo.InvariantCulture) + " has no name");
                }
            }
        }

        /// <summary>
        /// The description of the datalink.
        /// </summary>
        public string Description
        {
            get
            {
                var description = Interop.Pcap.pcap_datalink_val_to_description(Value);
                if (!string.IsNullOrEmpty(description))
                    return description;

                switch (Value)
                {
                    case DLT_PPP_WITH_DIR:
                        return "PPP with Directional Info";

                    default:
                        throw new InvalidOperationException("PcapDataLink " + Value.ToString(CultureInfo.InvariantCulture) + " has no description");
                }
            }
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            return Name + " (" + Description + ")";
        }

        /// <inheritdoc/>
        public bool Equals(PcapDataLink other)
        {
            return Equals(this, other);
        }

        /// <inheritdoc/>
        public override bool Equals(object obj)
        {
            if (!(obj is PcapDataLink link))
                return false;

            return Equals(link);
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            return _value.GetHashCode();
        }

        /// <summary>
        /// Determines whether the specified PcapDataLink objects are equal.
        /// </summary>
        public static bool operator ==(PcapDataLink dataLink1, PcapDataLink dataLink2)
        {
            return Equals(dataLink1, dataLink2);
        }

        /// <summary>
        /// Determines whether the specified PcapDataLink objects are unequal.
        /// </summary>
        public static bool operator !=(PcapDataLink dataLink1, PcapDataLink dataLink2)
        {
            return !Equals(dataLink1, dataLink2);
        }
#if NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static bool Equals(PcapDataLink dataLink1, PcapDataLink dataLink2)
        {
            return dataLink1._value == dataLink2._value;
        }

        private static int KindToValue(DataLinkKind kind)
        {
            switch (kind)
            {
                case DataLinkKind.Ethernet:
                    return Interop.Pcap.pcap_datalink_name_to_val("EN10MB");

                case DataLinkKind.IpV4:
                    return Interop.Pcap.pcap_datalink_name_to_val("RAW");

                case DataLinkKind.Docsis:
                    return Interop.Pcap.pcap_datalink_name_to_val("DOCSIS");

                case DataLinkKind.PointToPointProtocolWithDirection:
                    return DLT_PPP_WITH_DIR;

                case DataLinkKind.LinuxSll:
                    return Interop.Pcap.pcap_datalink_name_to_val("LINUX_SLL");

                default:
                    throw new NotSupportedException("PcapDataLink kind " + kind.ToString() + " is unsupported");
            }
        }
    }
}
