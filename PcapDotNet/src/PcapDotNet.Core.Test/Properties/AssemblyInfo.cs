using System.Reflection;
using System.Runtime.InteropServices;
using Xunit;
[assembly: AssemblyTrademark("Pcap.Net")]
[assembly: AssemblyCulture("")]

// Setting ComVisible to false makes the types in this assembly not visible 
// to COM componenets.  If you need to access a type in this assembly from 
// COM, set the ComVisible attribute to true on that type.
[assembly: ComVisible(false)]

// The following GUID is for the ID of the typelib if this project is exposed to COM
[assembly: Guid("bf31bff0-9bbf-431c-b79a-f0df4d758218")]
#if NETCOREAPP2_0_OR_GREATER
[assembly: CollectionBehavior(DisableTestParallelization = true)]
#endif
