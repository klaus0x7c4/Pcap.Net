using System;

namespace PcapDotNet.Core
{
    /// <summary>
    /// This is the base sampling method class.
    /// Every sampling method is defined by a method and an optional value, both for internal usage.
    /// </summary>
    public abstract class SamplingMethod
    {
        /// <summary>
        /// No sampling has to be done on the current capture.
        /// In this case, no sampling algorithms are applied to the current capture.
        /// </summary>
        public const int PCAP_SAMP_NOSAMP = 0;
        /// <summary>
        /// It defines that only 1 out of N packets must be returned to the user.
        /// In this case, the 'value' field of the 'pcap_samp' structure indicates the
        /// number of packets (minus 1) that must be discarded before one packet got accepted.
        /// IN other words, if 'value = 10', the first packet is returned to the caller, while
        /// the following 9 are discarded.
        /// </summary>
        public const int PCAP_SAMP_1_EVERY_N = 1;
        /// <summary>
        /// It defines that we have to return 1 packet every N milliseconds.
        /// In this case, the 'value' field of the 'pcap_samp' structure indicates the 'waiting
        /// time' in milliseconds before one packet got accepted.
        /// In other words, if 'value = 10', the first packet is returned to the caller; the next
        /// returned one will be the first packet that arrives when 10ms have elapsed.
        /// </summary>
        public const int PCAP_SAMP_FIRST_AFTER_N_MS = 2;

        internal abstract int Method { get; }

        internal abstract int Value { get; }
    }

    /// <summary>
    /// This sampling method defines that we have to return 1 packet every given time-interval.
    /// In other words, if the interval is set to 10 milliseconds, the first packet is returned to the caller; the next returned one will be the first packet that arrives when 10ms have elapsed.
    /// </summary>
    public sealed class SamplingMethodFirstAfterInterval : SamplingMethod
    {
        private readonly int _intervalInMilliseconds;

        /// <summary>
        /// Constructs by giving an interval in milliseconds.
        /// </summary>
        /// <param name="intervalInMilliseconds">The number of milliseconds to wait between packets sampled.</param>
        /// <exception cref="ArgumentOutOfRangeException">The given number of milliseconds is negative.</exception>
        public SamplingMethodFirstAfterInterval(int intervalInMilliseconds)
        {
            if (intervalInMilliseconds < 0)
                throw new ArgumentOutOfRangeException("intervalInMilliseconds", intervalInMilliseconds, "Must be non negative");
            _intervalInMilliseconds = intervalInMilliseconds;
        }

        /// <summary>
        /// Constructs by giving an interval as TimeSpan.
        /// </summary>
        /// <param name="interval">The time to wait between packets sampled.</param>
        /// <exception cref="ArgumentOutOfRangeException">The interval is negative or larger than 2^31 milliseconds.</exception>
        public SamplingMethodFirstAfterInterval(TimeSpan interval)
        {
            double intervalInMilliseconds = interval.TotalMilliseconds;
            if (intervalInMilliseconds > int.MaxValue)
                throw new ArgumentOutOfRangeException("interval", interval, "Must be smaller than " + TimeSpan.FromMilliseconds(int.MaxValue).ToString());
            if (intervalInMilliseconds < 0)
                throw new ArgumentOutOfRangeException("interval", interval, "Must be non negative");

            _intervalInMilliseconds = (int)intervalInMilliseconds;
        }

        internal override int Method => PCAP_SAMP_FIRST_AFTER_N_MS;

        /// <summary>
        /// Indicates the 'waiting time' in milliseconds before one packet got accepted. 
        /// In other words, if 'value = 10', the first packet is returned to the caller; the next returned one will be the first packet that arrives when 10ms have elapsed.
        /// </summary>
        internal override int Value => _intervalInMilliseconds;
    }

    /// <summary>
    /// No sampling has to be done on the current capture.
    /// In this case, no sampling algorithms are applied to the current capture.
    /// </summary>
    public sealed class SamplingMethodNone : SamplingMethod
    {
        internal override int Method => PCAP_SAMP_NOSAMP;

        internal override int Value => 0;
    }

    /// <summary>
    /// Defines that only 1 out of count packets must be returned to the user.
    /// In other words, if the count is set to 10, the first packet is returned to the caller, while the following 9 are discarded.
    /// </summary>
    public sealed class SamplingMethodOneEveryCount : SamplingMethod
    {
        private readonly int _count;

        /// <summary>
        /// Constructs by giving a count.
        /// </summary>
        /// <param name="count">1 packet out of count packets will be sampled (for each sampled packet, count-1 will be discarded).</param>
        /// <exception cref="ArgumentOutOfRangeException">The given count is non-positive.</exception>
        public SamplingMethodOneEveryCount(int count)
        {
            if (count <= 0)
                throw new ArgumentOutOfRangeException("count", count, "Must be positive");
            _count = count;
        }

        internal override int Method => PCAP_SAMP_1_EVERY_N;

        /// <summary>
        /// Indicates the number of packets (minus 1) that must be discarded before one packet got accepted. 
        /// In other words, if 'value = 10', the first packet is returned to the caller, while the following 9 are discarded.
        /// </summary>
        internal override int Value => _count;
    }


}
