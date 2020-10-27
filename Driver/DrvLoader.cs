using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MhyProt2Drv.Driver
{
    public class DrvLoader
    {
        private const string DriverDisplayName = "mhyprot2";
        private string DriverFileName = Environment.GetEnvironmentVariable("TEMP") + "\\mhyprot2.Sys";

        private IntPtr g_ServiceHandle;

        public void CopyFiles()
        {
            string currentDir = Environment.CurrentDirectory;
            string loader = System.IO.Path.Combine(currentDir, "mhyprot2.sys");
            try
            {
                System.IO.File.Copy(loader, DriverFileName, true);
            }
            catch (Exception)
            {
                Console.WriteLine($"[!] 无法复制文件到temp文件夹");
            }
        }
        public bool Load()
        {
            CopyFiles();
            IntPtr serviceHandle;
            if (ServiceHelper.OpenService(out serviceHandle, DriverDisplayName, 0x0020/*SERVICE_STOP*/ | 0x00010000/*DELETE*/))
            {
                //Console.WriteLine($"[!] Service already running");

                if (!ServiceHelper.StopService(serviceHandle))
                    //Console.WriteLine($"[!] Couldn't stop service");
                    Console.WriteLine($"[!] 无法停止服务");

                if (!ServiceHelper.DeleteService(serviceHandle))
                    Console.WriteLine($"[!] 无法删除服务");

                ServiceHelper.CloseServiceHandle(serviceHandle);
                return Load();
            }
            Console.WriteLine($"[+] 加载mhyprot2...");
            if (!ServiceHelper.CreateService(
                ref g_ServiceHandle,
                DriverDisplayName, DriverDisplayName,
                DriverFileName,
                (uint)NTAPI.SERVICE_ACCESS.SERVICE_ALL_ACCESS, 1/*SERVICE_KERNEL_DRIVER*/,
                (uint)NTAPI.SERVICE_START.SERVICE_DEMAND_START, 1/*SERVICE_ERROR_NORMAL*/))
            {
                Console.WriteLine($"[!] 无法为mhyprot2创建服务 - {Marshal.GetLastWin32Error():X}");
                return false;
            }
            if (!ServiceHelper.StartService(g_ServiceHandle))
            {
                int errorno = Marshal.GetLastWin32Error();
                if (errorno != 31)
                {
                    Console.WriteLine($"[!] 无法为mhyprot2启动服务 - {errorno:X}");
                    ServiceHelper.DeleteService(g_ServiceHandle);
                    return false;
                }
            }
            Console.WriteLine($"[+] mhyprot2成功启动");
            return true;
        }

        public bool UnLoad()
        {
            if (!ServiceHelper.StopService(g_ServiceHandle))
            {
                Console.WriteLine($"[!] 无法停止mhyprot2服务");
                return false;
            }
            if (!ServiceHelper.DeleteService(g_ServiceHandle))
            {
                Console.WriteLine($"[!] 无法删除mhyprot2服务");
                return false;
            }
            ServiceHelper.CloseServiceHandle(g_ServiceHandle);
            Console.WriteLine($"[+] 已卸载mhyprot2驱动");
            return true;
        }
    }
    public static class ServiceHelper
    {
        public static bool CreateService(
            ref IntPtr hService,
            string ServiceName,
            string DisplayName,
            string BinPath,
            uint DesiredAccess,
            uint ServiceType,
            uint StartType,
            uint ErrorControl)
        {
            IntPtr hSCManager = NTAPI.OpenSCManager(0, 0, 0x0002/*SC_MANAGER_CREATE_SERVICE*/);

            if (hSCManager == IntPtr.Zero)
                return false;

            hService = NTAPI.CreateServiceW(
                hSCManager,
                ServiceName, DisplayName,
                DesiredAccess,
                ServiceType, StartType,
                ErrorControl, BinPath,
                0, 0, 0, 0, 0, 0);

            NTAPI.CloseServiceHandle(hSCManager);

            return hService != IntPtr.Zero;
        }
        public static bool OpenService(out IntPtr hService, string szServiceName, uint DesiredAccess)
        {
            IntPtr hSCManager = NTAPI.OpenSCManager(0, 0, DesiredAccess);
            hService = NTAPI.OpenService(hSCManager, szServiceName, DesiredAccess);
            NTAPI.CloseServiceHandle(hSCManager);
            return hService != IntPtr.Zero;
        }
        public static bool StopService(IntPtr hService)
        {
            NTAPI.SERVICE_STATUS ServiceStatus = new NTAPI.SERVICE_STATUS();
            return NTAPI.ControlService(hService, NTAPI.SERVICE_CONTROL.STOP, ref ServiceStatus);
        }

        public static bool StartService(IntPtr hService) => NTAPI.StartService(hService, 0, null);
        public static bool DeleteService(IntPtr hService) => NTAPI.DeleteService(hService);
        public static void CloseServiceHandle(IntPtr hService) => NTAPI.CloseServiceHandle(hService);

        /// <summary>
        /// Native functions :)
        /// </summary>
    }
}
