using System.Runtime.InteropServices;
using System.Security.Principal;
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
namespace SeDebugPrivilege
{
    internal class Program
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGE NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct TOKEN_PRIVILEGE
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const uint TOKEN_QUERY = 0x00000008;
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        static void Main(string[] args)
        {
            // Check if the program is running as administrator
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                Console.WriteLine("The program must be run as administrator to enable SeDebugPrivilege.");
                Console.ReadKey();
                return;
            }

            // Get the current process handle
            IntPtr processHandle = GetCurrentProcess();

            // Open the current process token
            IntPtr tokenHandle;
            if (!OpenProcessToken(processHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tokenHandle))
            {
                Console.WriteLine("Failed to open process token: " + Marshal.GetLastWin32Error());
                Console.ReadKey();
                return;
            }

            // Lookup the LUID for the SeDebugPrivilege
            LUID seDebugPrivilegeLuid;
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out seDebugPrivilegeLuid))
            {
                Console.WriteLine("Failed to lookup SeDebugPrivilege LUID: " + Marshal.GetLastWin32Error());
                Console.ReadKey();
                return;
            }

            // Enable the SeDebugPrivilege
            // Enable the SeDebugPrivilege
            TOKEN_PRIVILEGE seDebugPrivilege = new TOKEN_PRIVILEGE
            {
                Luid = seDebugPrivilegeLuid,
                Attributes = SE_PRIVILEGE_ENABLED
            };
            if (!AdjustTokenPrivileges(tokenHandle, false, ref seDebugPrivilege, 0, IntPtr.Zero, IntPtr.Zero))
            {
                Console.WriteLine("Failed to adjust token privileges: " + Marshal.GetLastWin32Error());
                Console.ReadKey();
                return;
            }

            Console.WriteLine("Successfully aquired SeDebugPrivilege");
        }
    }
}

