using MhyProt2Drv.Driver;
using MhyProt2Drv.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MhyProt2Drv
{
    class Program
    {
        static void Main(string[] args)
        {
            DrvLoader loader = new DrvLoader();
            loader.Load();
            MhyProt2 mhyprot = new MhyProt2();
            mhyprot.OpenDrv();
            bool res = mhyprot.InitDrv((ulong)Process.GetCurrentProcess().Id);
            if (!res)
            {
                Console.WriteLine("Init Error!");
            }
            else
            {
                Console.WriteLine("Enuming module of csrss.exe");
                uint pid = (uint)Process.GetProcessesByName("csrss")[0].Id;
                List<MhyProtEnumModule> m = mhyprot.EnumProcessModule(pid);
                IntPtr baseAddr = IntPtr.Zero;
                foreach(MhyProtEnumModule sm in m)
                {
                    Console.WriteLine("ModuleName: " + sm.ModuleName + " ModulePath:" + sm.ModulePath + " BaseAddress:0x" + sm.BaseAddress.ToString("x2") + " Size:0x" + sm.SizeOfImage.ToString("x2"));
                    if (sm.ModuleName == "csrss.exe") baseAddr = sm.BaseAddress;
                }
                Memory mem = new Memory(mhyprot, pid);
                long currentTicks = DateTime.Now.Ticks;
                Console.WriteLine("Reading memory of csrss.exe");
                for (int i = 0; i < 1000; i++)
                {
                    mem.Read(baseAddr, 1024);
                }
                Console.WriteLine("Read memory 1000 times tooks total " + ((DateTime.Now.Ticks - currentTicks) / 10000).ToString() + "ms");
            }

            Console.ReadKey();
            mhyprot.CloseHandle();
            loader.UnLoad();
        }
    }
}
