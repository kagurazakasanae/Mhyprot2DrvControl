using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MhyProt2Drv
{
    public unsafe static class NTAPI
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr CreateFileA(
              string lpFileName,
              uint dwDesiredAccess,
              uint dwShareMode,
             IntPtr lpSecurityAttributes,
             uint dwCreationDisposition,
             uint dwFlagsAndAttributes,
             IntPtr hTemplateFile);

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(uint machineName, uint databaseName, uint dwAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);
        [DllImport("ntdll.dll", CharSet = CharSet.Auto)]
        public static extern uint NtOpenFile(IntPtr* FileHandle, uint DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, IO_STATUS_BLOCK* IoStatusBlock, uint ShareAccess, uint OpenOptions);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ControlService(IntPtr hService, SERVICE_CONTROL dwControl, ref SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(
            IntPtr hService,
            int dwNumServiceArgs,
            string[] lpServiceArgVectors
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeleteService(IntPtr hService);
        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool DeviceIoControl(
                IntPtr hDevice,
                uint dwIoControlCode,
                void* lpInBuffer,
                uint nInBufferSize,
                void* lpOutBuffer,
                uint nOutBufferSize,
                ulong* lpBytesReturned,
                uint lpOverlapped);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode, IntPtr lpInBuffer, uint nInBufferSize, IntPtr lpOutBuffer, uint nOutBufferSize, ulong* lpBytesReturned, uint lpOverlapped);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateServiceW(
            IntPtr hSCManager,
            string lpServiceName,
            string lpDisplayName,
            uint dwDesiredAccess,
            uint dwServiceType,
            uint dwStartType,
            uint dwErrorControl,
            string lpBinaryPathName,
            uint lpLoadOrderGroup,
            uint lpdwTagId,
            uint lpdwTagId1,
            uint lpDependencies,
            uint lpServiceStartName,
            uint lpPassword);

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct SERVICE_STATUS
        {
            public SERVICE_TYPE dwServiceType;
            public SERVICE_STATE dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IO_STATUS_BLOCK
        {
            public uint status;
            public IntPtr information;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            private IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }
        [Flags]
        public enum SERVICE_TYPE : int
        {
            SERVICE_KERNEL_DRIVER = 0x00000001,
            SERVICE_FILE_SYSTEM_DRIVER = 0x00000002,
            SERVICE_WIN32_OWN_PROCESS = 0x00000010,
            SERVICE_WIN32_SHARE_PROCESS = 0x00000020,
            SERVICE_INTERACTIVE_PROCESS = 0x00000100
        }
        [Flags]
        public enum SERVICE_CONTROL : uint
        {
            STOP = 0x00000001,
            PAUSE = 0x00000002,
            CONTINUE = 0x00000003,
            INTERROGATE = 0x00000004,
            SHUTDOWN = 0x00000005,
            PARAMCHANGE = 0x00000006,
            NETBINDADD = 0x00000007,
            NETBINDREMOVE = 0x00000008,
            NETBINDENABLE = 0x00000009,
            NETBINDDISABLE = 0x0000000A,
            DEVICEEVENT = 0x0000000B,
            HARDWAREPROFILECHANGE = 0x0000000C,
            POWEREVENT = 0x0000000D,
            SESSIONCHANGE = 0x0000000E
        }
        public enum SERVICE_STATE : uint
        {
            SERVICE_STOPPED = 0x00000001,
            SERVICE_START_PENDING = 0x00000002,
            SERVICE_STOP_PENDING = 0x00000003,
            SERVICE_RUNNING = 0x00000004,
            SERVICE_CONTINUE_PENDING = 0x00000005,
            SERVICE_PAUSE_PENDING = 0x00000006,
            SERVICE_PAUSED = 0x00000007
        }
        public enum SERVICE_ACCESS : uint
        {
            /// <summary>
            /// Required to call the QueryServiceConfig and 
            /// QueryServiceConfig2 functions to query the service configuration.
            /// </summary>
            SERVICE_QUERY_CONFIG = 0x00001,

            /// <summary>
            /// Required to call the ChangeServiceConfig or ChangeServiceConfig2 function 
            /// to change the service configuration. Because this grants the caller 
            /// the right to change the executable file that the system runs, 
            /// it should be granted only to administrators.
            /// </summary>
            SERVICE_CHANGE_CONFIG = 0x00002,

            /// <summary>
            /// Required to call the QueryServiceStatusEx function to ask the service 
            /// control manager about the status of the service.
            /// </summary>
            SERVICE_QUERY_STATUS = 0x00004,

            /// <summary>
            /// Required to call the EnumDependentServices function to enumerate all 
            /// the services dependent on the service.
            /// </summary>
            SERVICE_ENUMERATE_DEPENDENTS = 0x00008,

            /// <summary>
            /// Required to call the StartService function to start the service.
            /// </summary>
            SERVICE_START = 0x00010,

            /// <summary>
            ///     Required to call the ControlService function to stop the service.
            /// </summary>
            SERVICE_STOP = 0x00020,

            /// <summary>
            /// Required to call the ControlService function to pause or continue 
            /// the service.
            /// </summary>
            SERVICE_PAUSE_CONTINUE = 0x00040,

            /// <summary>
            /// Required to call the EnumDependentServices function to enumerate all
            /// the services dependent on the service.
            /// </summary>
            SERVICE_INTERROGATE = 0x00080,

            /// <summary>
            /// Required to call the ControlService function to specify a user-defined
            /// control code.
            /// </summary>
            SERVICE_USER_DEFINED_CONTROL = 0x00100,

            /// <summary>
            /// Includes STANDARD_RIGHTS_REQUIRED in addition to all access rights in this table.
            /// </summary>
            SERVICE_ALL_ACCESS = (ACCESS_MASK.STANDARD_RIGHTS_REQUIRED |
                SERVICE_QUERY_CONFIG |
                SERVICE_CHANGE_CONFIG |
                SERVICE_QUERY_STATUS |
                SERVICE_ENUMERATE_DEPENDENTS |
                SERVICE_START |
                SERVICE_STOP |
                SERVICE_PAUSE_CONTINUE |
                SERVICE_INTERROGATE |
                SERVICE_USER_DEFINED_CONTROL),

            GENERIC_READ = ACCESS_MASK.STANDARD_RIGHTS_READ |
                SERVICE_QUERY_CONFIG |
                SERVICE_QUERY_STATUS |
                SERVICE_INTERROGATE |
                SERVICE_ENUMERATE_DEPENDENTS,

            GENERIC_WRITE = ACCESS_MASK.STANDARD_RIGHTS_WRITE |
                SERVICE_CHANGE_CONFIG,

            GENERIC_EXECUTE = ACCESS_MASK.STANDARD_RIGHTS_EXECUTE |
                SERVICE_START |
                SERVICE_STOP |
                SERVICE_PAUSE_CONTINUE |
                SERVICE_USER_DEFINED_CONTROL,

            /// <summary>
            /// Required to call the QueryServiceObjectSecurity or 
            /// SetServiceObjectSecurity function to access the SACL. The proper
            /// way to obtain this access is to enable the SE_SECURITY_NAME 
            /// privilege in the caller's current access token, open the handle 
            /// for ACCESS_SYSTEM_SECURITY access, and then disable the privilege.
            /// </summary>
            ACCESS_SYSTEM_SECURITY = ACCESS_MASK.ACCESS_SYSTEM_SECURITY,

            /// <summary>
            /// Required to call the DeleteService function to delete the service.
            /// </summary>
            DELETE = ACCESS_MASK.DELETE,

            /// <summary>
            /// Required to call the QueryServiceObjectSecurity function to query
            /// the security descriptor of the service object.
            /// </summary>
            READ_CONTROL = ACCESS_MASK.READ_CONTROL,

            /// <summary>
            /// Required to call the SetServiceObjectSecurity function to modify
            /// the Dacl member of the service object's security descriptor.
            /// </summary>
            WRITE_DAC = ACCESS_MASK.WRITE_DAC,

            /// <summary>
            /// Required to call the SetServiceObjectSecurity function to modify 
            /// the Owner and Group members of the service object's security 
            /// descriptor.
            /// </summary>
            WRITE_OWNER = ACCESS_MASK.WRITE_OWNER,
        }

        [Flags]
        public enum ACCESS_MASK : uint
        {
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            SYNCHRONIZE = 0x00100000,

            STANDARD_RIGHTS_REQUIRED = 0x000F0000,

            STANDARD_RIGHTS_READ = 0x00020000,
            STANDARD_RIGHTS_WRITE = 0x00020000,
            STANDARD_RIGHTS_EXECUTE = 0x00020000,

            STANDARD_RIGHTS_ALL = 0x001F0000,

            SPECIFIC_RIGHTS_ALL = 0x0000FFFF,

            ACCESS_SYSTEM_SECURITY = 0x01000000,

            MAXIMUM_ALLOWED = 0x02000000,

            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000,

            DESKTOP_READOBJECTS = 0x00000001,
            DESKTOP_CREATEWINDOW = 0x00000002,
            DESKTOP_CREATEMENU = 0x00000004,
            DESKTOP_HOOKCONTROL = 0x00000008,
            DESKTOP_JOURNALRECORD = 0x00000010,
            DESKTOP_JOURNALPLAYBACK = 0x00000020,
            DESKTOP_ENUMERATE = 0x00000040,
            DESKTOP_WRITEOBJECTS = 0x00000080,
            DESKTOP_SWITCHDESKTOP = 0x00000100,

            WINSTA_ENUMDESKTOPS = 0x00000001,
            WINSTA_READATTRIBUTES = 0x00000002,
            WINSTA_ACCESSCLIPBOARD = 0x00000004,
            WINSTA_CREATEDESKTOP = 0x00000008,
            WINSTA_WRITEATTRIBUTES = 0x00000010,
            WINSTA_ACCESSGLOBALATOMS = 0x00000020,
            WINSTA_EXITWINDOWS = 0x00000040,
            WINSTA_ENUMERATE = 0x00000100,
            WINSTA_READSCREEN = 0x00000200,

            WINSTA_ALL_ACCESS = 0x0000037F
        }

        /// <summary>
        /// Service start options
        /// </summary>
        public enum SERVICE_START : uint
        {
            /// <summary>
            /// A device driver started by the system loader. This value is valid
            /// only for driver services.
            /// </summary>
            SERVICE_BOOT_START = 0x00000000,

            /// <summary>
            /// A device driver started by the IoInitSystem function. This value 
            /// is valid only for driver services.
            /// </summary>
            SERVICE_SYSTEM_START = 0x00000001,

            /// <summary>
            /// A service started automatically by the service control manager 
            /// during system startup. For more information, see Automatically 
            /// Starting Services.
            /// </summary>         
            SERVICE_AUTO_START = 0x00000002,

            /// <summary>
            /// A service started by the service control manager when a process 
            /// calls the StartService function. For more information, see 
            /// Starting Services on Demand.
            /// </summary>
            SERVICE_DEMAND_START = 0x00000003,

            /// <summary>
            /// A service that cannot be started. Attempts to start the service
            /// result in the error code ERROR_SERVICE_DISABLED.
            /// </summary>
            SERVICE_DISABLED = 0x00000004,
        }
        [Flags]
        public enum SERVICE_ACCEPT : uint
        {
            STOP = 0x00000001,
            PAUSE_CONTINUE = 0x00000002,
            SHUTDOWN = 0x00000004,
            PARAMCHANGE = 0x00000008,
            NETBINDCHANGE = 0x00000010,
            HARDWAREPROFILECHANGE = 0x00000020,
            POWEREVENT = 0x00000040,
            SESSIONCHANGE = 0x00000080,
        }
        public static uint STATUS_SUCCESS = 0x00000000;
        public static uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr memmove(IntPtr dest, IntPtr src, ulong count);
        [DllImport("ntdll.dll")]
        public static extern int ZwUnmapViewOfSection(IntPtr hProcess, IntPtr BaseAddress);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [StructLayout(LayoutKind.Explicit, Size = 8)]
        public struct LARGE_INTEGER
        {
            //[FieldOffset(0)] public long QuadPart;
            [FieldOffset(0)] public int LowPart;
            [FieldOffset(4)] public int HighPart;
        }
        [DllImport("ntdll.dll", EntryPoint = "ZwOpenSection")]
        public static extern uint ZwOpenSection(out IntPtr sectionHandle, uint desiredAccess, ref OBJECT_ATTRIBUTES attributes);
        [DllImport("ntdll.dll", EntryPoint = "ZwMapViewOfSection")]
        public unsafe static extern uint ZwMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, int zeroBits, ulong commitSize, LARGE_INTEGER* stuff, ref ulong viewSize, int inheritDispo, uint alloctype, uint prot);
        [DllImport("user32.dll", EntryPoint = "SetWindowPos")]
        public static extern IntPtr SetWindowPos(IntPtr hWnd, int hWndInsertAfter, int x, int Y, int cx, int cy, int wFlags);
        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, ulong lpBaseAddress, byte[] lpBuffer, uint dwSize, int lpNumberOfBytesRead = 0);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("user32.dll", EntryPoint = "FindWindow")]
        public extern static IntPtr FindWindow(string lpClassName, string lpWindowName);

        public delegate bool CallBack(int hwnd, int lParam);

        [DllImport("user32.dll")]
        public static extern int EnumWindows(CallBack x, int y);


        [DllImport("user32.dll")]
        public static extern void mouse_event(uint dwFlags, int dx, int dy, uint dwData, int dwExtraInfo);


        [DllImport("user32.dll")]
        public static extern int GetWindowText(int hwnd, StringBuilder lptrString, int nMaxCount);


        [DllImport("psapi.dll", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        /*
        得到指定进程中每个模块的句柄

        需要指定一个大的存储HMODULE值的数组。因为较难预计进程中有多少个模块。比较lpcbNeeded和cb，如果lpcbNeeded大于cb，增加lphModule数组的大小后再调用EnumProcessModules。
        参数

        hProcess	-	[in]进程句柄。
        lphModule	-	[out]指向保存模块句柄数组的指针。
        cb	-	[in]lphmodule数组的大小，字节为单位。
        lpcbNeeded	-	[out]存储所有模块句柄的lphmodule数组的大小，字节为单位。
        返回值

        成功返回非零值，失败返回零。调用GetLastError得到错误信息。
        */
        public static extern bool EnumProcessModules(IntPtr hProcess, [Out] IntPtr lphModule, uint cb, out uint lpcbNeeded);

        [DllImport("psapi.dll")]
        public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, [In][MarshalAs(UnmanagedType.U4)] int nSize);

        [DllImport("psapi.dll", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        /*
        参数

        hProcess	-	[in]包含模块的进程的句柄。
        hModule	-	[in]模块句柄。
        lpmodinfo	-	[out]指向存放模块信息的MODULEINFO的指针。
        cb	-	[in]MODULEINFO结构的大小，字节为单位。
        返回值

        成功返回非零值。失败返回0。调用GetLastError得到错误信息。
         */
        public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out _MODULEINFO lpModInfo, int cb);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowLong(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll")]
        public static extern int SetWindowLong(IntPtr hWnd, int nIndex, IntPtr dwNewLong);

        [DllImport("user32.dll")]
        public static extern bool SetLayeredWindowAttributes(IntPtr hwnd, uint crKey, byte bAlpha, uint dwFlags);

        [DllImport("dwmapi.dll")]
        public static extern void DwmExtendFrameIntoClientArea(IntPtr hWnd, ref Margins pMargins);

        [DllImport("Gdi32.dll", CharSet = CharSet.Auto, ExactSpelling = true)]
        public static extern int GetDeviceCaps(IntPtr hDC, int nIndex);

        [DllImport("User32.dll")]
        public extern static IntPtr GetDesktopWindow();

        [DllImport("User32.dll")]
        public static extern IntPtr GetDC(IntPtr hWnd);

        [DllImport("ntdll.dll", SetLastError = true)]
        public unsafe static extern uint RtlGetVersion(_OSVERSIONINFOEXW* lpVersionInformation);

        [DllImport("ntdll.dll", SetLastError = true)]
        public unsafe static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, void* processInformation, int processInformationLength, IntPtr returnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtQuerySystemInformation(uint InfoClass, ulong Info, uint Size, out uint Length);

        [DllImport("ntdll.dll", EntryPoint = "ZwQuerySystemInformation")]
        public static extern uint ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll", EntryPoint = "ZwDuplicateObject")]
        public static extern uint ZwDuplicateObject(IntPtr SourceProcessHandle, IntPtr SourceHandle, IntPtr TargetProcessHandle, out IntPtr TargetHandle, ulong DesiredAccess, ulong HandleAttributes, ulong Options);

        [DllImport("ntdll.dll")]
        public static extern uint RtlNtStatusToDosError(uint Status);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern ulong LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern ulong GetProcAddress(ulong hModule, string procName);

        [DllImport("kernel32.dll", EntryPoint = "GetProcessId", CharSet = CharSet.Auto)]
        public static extern int GetProcessId(IntPtr handle);

        [DllImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
        public enum SYSTEM_INFORMATION_CLASS
        {
            SystemBasicInformation = 0x0000,
            SystemProcessorInformation = 0x0001,
            SystemPerformanceInformation = 0x0002,
            SystemTimeOfDayInformation = 0x0003,
            SystemPathInformation = 0x0004,
            SystemProcessInformation = 0x0005,
            SystemCallCountInformation = 0x0006,
            SystemDeviceInformation = 0x0007,
            SystemProcessorPerformanceInformation = 0x0008,
            SystemFlagsInformation = 0x0009,
            SystemCallTimeInformation = 0x000A,
            SystemModuleInformation = 0x000B,
            SystemLocksInformation = 0x000C,
            SystemStackTraceInformation = 0x000D,
            SystemPagedPoolInformation = 0x000E,
            SystemNonPagedPoolInformation = 0x000F,
            SystemHandleInformation = 0x0010,
            SystemObjectInformation = 0x0011,
            SystemPageFileInformation = 0x0012,
            SystemVdmInstemulInformation = 0x0013,
            SystemVdmBopInformation = 0x0014,
            SystemFileCacheInformation = 0x0015,
            SystemPoolTagInformation = 0x0016,
            SystemInterruptInformation = 0x0017,
            SystemDpcBehaviorInformation = 0x0018,
            SystemFullMemoryInformation = 0x0019,
            SystemLoadGdiDriverInformation = 0x001A,
            SystemUnloadGdiDriverInformation = 0x001B,
            SystemTimeAdjustmentInformation = 0x001C,
            SystemSummaryMemoryInformation = 0x001D,
            SystemMirrorMemoryInformation = 0x001E,
            SystemPerformanceTraceInformation = 0x001F,
            SystemCrashDumpInformation = 0x0020,
            SystemExceptionInformation = 0x0021,
            SystemCrashDumpStateInformation = 0x0022,
            SystemKernelDebuggerInformation = 0x0023,
            SystemContextSwitchInformation = 0x0024,
            SystemRegistryQuotaInformation = 0x0025,
            SystemExtendServiceTableInformation = 0x0026,
            SystemPrioritySeperation = 0x0027,
            SystemVerifierAddDriverInformation = 0x0028,
            SystemVerifierRemoveDriverInformation = 0x0029,
            SystemProcessorIdleInformation = 0x002A,
            SystemLegacyDriverInformation = 0x002B,
            SystemCurrentTimeZoneInformation = 0x002C,
            SystemLookasideInformation = 0x002D,
            SystemTimeSlipNotification = 0x002E,
            SystemSessionCreate = 0x002F,
            SystemSessionDetach = 0x0030,
            SystemSessionInformation = 0x0031,
            SystemRangeStartInformation = 0x0032,
            SystemVerifierInformation = 0x0033,
            SystemVerifierThunkExtend = 0x0034,
            SystemSessionProcessInformation = 0x0035,
            SystemLoadGdiDriverInSystemSpace = 0x0036,
            SystemNumaProcessorMap = 0x0037,
            SystemPrefetcherInformation = 0x0038,
            SystemExtendedProcessInformation = 0x0039,
            SystemRecommendedSharedDataAlignment = 0x003A,
            SystemComPlusPackage = 0x003B,
            SystemNumaAvailableMemory = 0x003C,
            SystemProcessorPowerInformation = 0x003D,
            SystemEmulationBasicInformation = 0x003E,
            SystemEmulationProcessorInformation = 0x003F,
            SystemExtendedHandleInformation = 0x0040,
            SystemLostDelayedWriteInformation = 0x0041,
            SystemBigPoolInformation = 0x0042,
            SystemSessionPoolTagInformation = 0x0043,
            SystemSessionMappedViewInformation = 0x0044,
            SystemHotpatchInformation = 0x0045,
            SystemObjectSecurityMode = 0x0046,
            SystemWatchdogTimerHandler = 0x0047,
            SystemWatchdogTimerInformation = 0x0048,
            SystemLogicalProcessorInformation = 0x0049,
            SystemWow64SharedInformationObsolete = 0x004A,
            SystemRegisterFirmwareTableInformationHandler = 0x004B,
            SystemFirmwareTableInformation = 0x004C,
            SystemModuleInformationEx = 0x004D,
            SystemVerifierTriageInformation = 0x004E,
            SystemSuperfetchInformation = 0x004F,
            SystemMemoryListInformation = 0x0050, // SYSTEM_MEMORY_LIST_INFORMATION
            SystemFileCacheInformationEx = 0x0051,
            SystemThreadPriorityClientIdInformation = 0x0052,
            SystemProcessorIdleCycleTimeInformation = 0x0053,
            SystemVerifierCancellationInformation = 0x0054,
            SystemProcessorPowerInformationEx = 0x0055,
            SystemRefTraceInformation = 0x0056,
            SystemSpecialPoolInformation = 0x0057,
            SystemProcessIdInformation = 0x0058,
            SystemErrorPortInformation = 0x0059,
            SystemBootEnvironmentInformation = 0x005A,
            SystemHypervisorInformation = 0x005B,
            SystemVerifierInformationEx = 0x005C,
            SystemTimeZoneInformation = 0x005D,
            SystemImageFileExecutionOptionsInformation = 0x005E,
            SystemCoverageInformation = 0x005F,
            SystemPrefetchPatchInformation = 0x0060,
            SystemVerifierFaultsInformation = 0x0061,
            SystemSystemPartitionInformation = 0x0062,
            SystemSystemDiskInformation = 0x0063,
            SystemProcessorPerformanceDistribution = 0x0064,
            SystemNumaProximityNodeInformation = 0x0065,
            SystemDynamicTimeZoneInformation = 0x0066,
            SystemCodeIntegrityInformation = 0x0067,
            SystemProcessorMicrocodeUpdateInformation = 0x0068,
            SystemProcessorBrandString = 0x0069,
            SystemVirtualAddressInformation = 0x006A,
            SystemLogicalProcessorAndGroupInformation = 0x006B,
            SystemProcessorCycleTimeInformation = 0x006C,
            SystemStoreInformation = 0x006D,
            SystemRegistryAppendString = 0x006E,
            SystemAitSamplingValue = 0x006F,
            SystemVhdBootInformation = 0x0070,
            SystemCpuQuotaInformation = 0x0071,
            SystemNativeBasicInformation = 0x0072,
            SystemErrorPortTimeouts = 0x0073,
            SystemLowPriorityIoInformation = 0x0074,
            SystemBootEntropyInformation = 0x0075,
            SystemVerifierCountersInformation = 0x0076,
            SystemPagedPoolInformationEx = 0x0077,
            SystemSystemPtesInformationEx = 0x0078,
            SystemNodeDistanceInformation = 0x0079,
            SystemAcpiAuditInformation = 0x007A,
            SystemBasicPerformanceInformation = 0x007B,
            SystemQueryPerformanceCounterInformation = 0x007C,
            SystemSessionBigPoolInformation = 0x007D,
            SystemBootGraphicsInformation = 0x007E,
            SystemScrubPhysicalMemoryInformation = 0x007F,
            SystemBadPageInformation = 0x0080,
            SystemProcessorProfileControlArea = 0x0081,
            SystemCombinePhysicalMemoryInformation = 0x0082,
            SystemEntropyInterruptTimingInformation = 0x0083,
            SystemConsoleInformation = 0x0084,
            SystemPlatformBinaryInformation = 0x0085,
            SystemThrottleNotificationInformation = 0x0086,
            SystemHypervisorProcessorCountInformation = 0x0087,
            SystemDeviceDataInformation = 0x0088,
            SystemDeviceDataEnumerationInformation = 0x0089,
            SystemMemoryTopologyInformation = 0x008A,
            SystemMemoryChannelInformation = 0x008B,
            SystemBootLogoInformation = 0x008C,
            SystemProcessorPerformanceInformationEx = 0x008D,
            SystemSpare0 = 0x008E,
            SystemSecureBootPolicyInformation = 0x008F,
            SystemPageFileInformationEx = 0x0090,
            SystemSecureBootInformation = 0x0091,
            SystemEntropyInterruptTimingRawInformation = 0x0092,
            SystemPortableWorkspaceEfiLauncherInformation = 0x0093,
            SystemFullProcessInformation = 0x0094,
            MaxSystemInfoClass = 0x0095
        }
        public enum DuplicateOptions : ulong
        {
            DUPLICATE_CLOSE_SOURCE = (0x00000001),// Closes the source handle. This occurs regardless of any error status returned.
            DUPLICATE_SAME_ACCESS = (0x00000002) //Ignores the dwDesiredAccess parameter. The duplicate handle has the same access as the source handle.
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_HANDLE_ENTRY
        {
            public int OwnerPid;
            public byte ObjectType;
            public byte HandleFlags;
            public short HandleValue;
            public int ObjectPointer;
            public int AccessMask;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_BASIC_INFORMATION
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 24)]
            public byte[] Reserved1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public IntPtr[] Reserved2;
            public Char NumberOfProcessors;
        }


        public struct Margins
        {
            public int Left, Right, Top, Bottom;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct _MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public uint SizeOfImage;
            public IntPtr EntryPoint;
        }




        [DllImport("user32.dll")]
        public static extern IntPtr SetActiveWindow(IntPtr hwnd);//设置活动窗体

        [StructLayout(LayoutKind.Sequential)]
        public struct RECT
        {
            public int Left;                             //最左坐标
            public int Top;                             //最上坐标
            public int Right;                           //最右坐标
            public int Bottom;                        //最下坐标
        }

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetWindowRect(IntPtr hWnd, ref RECT lpRect);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetClientRect(IntPtr hWnd, ref RECT lpRect);

        public const int WS_EX_NOACTIVATE = 0x08000000;

        public const int GWL_EXSTYLE = -20;

        public const int WS_EX_LAYERED = 0x80000;

        public const int WS_EX_TRANSPARENT = 0x20;

        public const int LWA_ALPHA = 0x2;

        public const int LWA_COLORKEY = 0x1;

        [StructLayout(LayoutKind.Sequential)]
        public struct _HANDLE_TABLE_ENTRY
        {
            public ulong Object;
            public ulong GrantedAccess;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ProcessContext
        {
            public uint ProcessId;
            public ulong DirectoryBase;
            public ulong KernelEntry;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct _OSVERSIONINFOEXW
        {
            public uint dwOSVersionInfoSize;
            public uint dwMajorVersion;
            public uint dwMinorVersion;
            public uint dwBuildNumber;
            public uint dwPlatformId;
            public fixed byte szCSDVersion[128 * 2/*WCHAR*/];     // Maintenance string for PSS usage
            public ushort wServicePackMajor;
            public ushort wServicePackMinor;
            public ushort wSuiteMask;
            public byte wProductType;
            public byte wReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _RTL_PROCESS_MODULES
        {
            public uint NumberOfModules;
            public _RTL_PROCESS_MODULE_INFORMATION Modules;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct _RTL_PROCESS_MODULE_INFORMATION
        {
            public void* Section;
            public void* MappedBase;
            public void* ImageBase;
            public uint ImageSize;
            public uint Flags;
            public ushort LoadOrderIndex;
            public ushort InitOrderIndex;
            public ushort LoadCount;
            public ushort OffsetToFileName;
            public fixed sbyte FullPathName[256];
        }
        public struct OBJECT_ATTRIBUTES
        {
            public Int32 Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;

        }
    }
}
