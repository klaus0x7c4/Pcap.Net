namespace PcapDotNet.Core
{
    /// <summary>
    /// The base of all device addresses.
    /// Contains the family (type) of the address.
    /// </summary>
    public abstract class SocketAddress
    {
        private readonly SocketAddressFamily _family;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        protected SocketAddress(SocketAddressFamily family)
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
        {
            _family = family;
        }

        /// <summary>
        /// Family (type) of the socket address.
        /// </summary>
        public SocketAddressFamily Family => _family;

        /// <inheritdoc/>
        public override string ToString()
        {
            return Family.ToString();
        }
    }

}
