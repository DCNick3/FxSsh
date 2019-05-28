using System;
using System.Runtime.InteropServices;
using static MiniTerm.Native.ProcessApi;

namespace MiniTerm
{
    /// <summary>
    ///     Support for starting and configuring processes.
    /// </summary>
    /// <remarks>
    ///     Possible to replace with managed code? The key is being able to provide the PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
    ///     attribute
    /// </remarks>
    internal static class ProcessFactory
    {
        /// <summary>
        ///     Start and configure a process. The return value represents the process and should be disposed.
        /// </summary>
        internal static Process Start(string command, IntPtr attributes, IntPtr hPC)
        {
            var startupInfo = ConfigureProcessThread(hPC, attributes);
            var processInfo = RunProcess(ref startupInfo, command);
            return new Process(startupInfo, processInfo);
        }

        private static STARTUPINFOEX ConfigureProcessThread(IntPtr hPC, IntPtr attributes)
        {
            // this method implements the behavior described in https://docs.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session#preparing-for-creation-of-the-child-process

            var lpSize = IntPtr.Zero;
            var success = InitializeProcThreadAttributeList(
                IntPtr.Zero,
                1,
                0,
                ref lpSize
            );
            if (success || lpSize == IntPtr.Zero
            ) // we're not expecting `success` here, we just want to get the calculated lpSize
                throw new InvalidOperationException("Could not calculate the number of bytes for the attribute list. " +
                                                    Marshal.GetLastWin32Error());

            var startupInfo = new STARTUPINFOEX();
            startupInfo.StartupInfo.cb = Marshal.SizeOf<STARTUPINFOEX>();
            startupInfo.lpAttributeList = Marshal.AllocHGlobal(lpSize);

            success = InitializeProcThreadAttributeList(
                startupInfo.lpAttributeList,
                1,
                0,
                ref lpSize
            );
            if (!success)
                throw new InvalidOperationException("Could not set up attribute list. " + Marshal.GetLastWin32Error());

            success = UpdateProcThreadAttribute(
                startupInfo.lpAttributeList,
                0,
                attributes,
                hPC,
                (IntPtr) IntPtr.Size,
                IntPtr.Zero,
                IntPtr.Zero
            );
            if (!success)
                throw new InvalidOperationException("Could not set pseudoconsole thread attribute. " +
                                                    Marshal.GetLastWin32Error());

            return startupInfo;
        }

        private static PROCESS_INFORMATION RunProcess(ref STARTUPINFOEX sInfoEx, string commandLine)
        {
            var securityAttributeSize = Marshal.SizeOf<SECURITY_ATTRIBUTES>();
            var pSec = new SECURITY_ATTRIBUTES {nLength = securityAttributeSize};
            var tSec = new SECURITY_ATTRIBUTES {nLength = securityAttributeSize};
            var success = CreateProcess(
                null,
                commandLine,
                ref pSec,
                ref tSec,
                false,
                EXTENDED_STARTUPINFO_PRESENT,
                IntPtr.Zero,
                null,
                ref sInfoEx,
                out var pInfo
            );
            if (!success)
                throw new InvalidOperationException("Could not create process. " + Marshal.GetLastWin32Error());

            return pInfo;
        }
    }
}