using System;
using System.Threading;
using System.Threading.Tasks;

namespace PcapDotNet.Core.Extensions
{
    /// <summary>
    /// Extension methods for Task class.
    /// </summary>
    public static class TaskExtensions
    {
        /// <summary>
        /// Creates a Task that will complete after a time delay.
        /// </summary>
        /// <param name="delay">The time span to wait before completing the returned Task</param>
        /// <returns>A Task that represents the time delay</returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="delay"/> is less than -1 or greater than the maximum allowed timer duration.
        /// </exception>
        /// <remarks>
        /// After the specified time delay, the Task is completed in RanToCompletion state.
        /// </remarks>
        public static Task Delay(TimeSpan delay)
        {
            // timer inaccuracy https://github.com/dotnet/runtime/issues/100455
#if NETCOREAPP1_0_OR_GREATER
            return Task.Delay(delay.Add(TimeSpan.FromMilliseconds(1))); // +1 is to workaround, random return less than 1 ms too early
#else
            var tcs = new TaskCompletionSource<object>();
            Timer timer = null;
            timer = new Timer(_ =>
                {
                    tcs.SetResult(null);
                    timer.Dispose(); // prevent GC
                });
            timer.Change((long)delay.TotalMilliseconds + 1, -1); // +1 is to workaround, random return less than 1 ms too early
            return tcs.Task;
#endif
        }
    }
}
