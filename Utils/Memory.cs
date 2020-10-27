using MhyProt2Drv.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MhyProt2Drv.Utils
{
    public class Memory
    {
        private MhyProt2 drv;
        private uint pid;

        public Memory(MhyProt2 drv, uint pid)
        {
            this.drv = drv;
            this.pid = pid;
        }
        public byte[] Read(IntPtr Address, uint length)
        {
            IntPtr readptr = Marshal.AllocHGlobal((IntPtr)length);
            uint read = drv.RWMemory(0, pid, readptr, Address, length);
            if (read == 0) throw new Exception("Read failed");
            return drv.PtrToByte(readptr, read);
        }
        public uint Write(IntPtr Address, byte[] data)
        {
            IntPtr writeptr = drv.ByteToPtr(data);
            uint write = drv.RWMemory(1, pid, Address, writeptr, (uint)data.Length);
            if (write == 0) throw new Exception("Write failed");
            return write;
        }
        public T Read<T>(IntPtr Address)
        {
            var size = (uint)Marshal.SizeOf(typeof(T));
            var data = Read(Address, size);
            return GetStructure<T>(data);
        }
        public void Write<T>(T input, IntPtr Address)
        {
            int size = Marshal.SizeOf(input);
            byte[] arr = new byte[size];

            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(input, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);
            Write(Address, arr);
        }
        public string ReadString(IntPtr address)
        {
            byte[] numArray = Read(address, 255);
            var str = Encoding.Default.GetString(numArray);

            if (str.Contains('\0'))
                str = str.Substring(0, str.IndexOf('\0'));
            return str;
        }
        public string ReadUnicodeString(IntPtr address)
        {
            byte[] numArray = Read(address, 255);
            var str = Encoding.Unicode.GetString(numArray);

            if (str.Contains('\0'))
                str = str.Substring(0, str.IndexOf('\0'));
            return str;
        }
        public static T GetStructure<T>(byte[] bytes)
        {
            var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            var structure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
            return structure;
        }
        public static T GetStructure<T>(byte[] bytes, int index)
        {
            int size = Marshal.SizeOf(typeof(T));
            byte[] tmp = new byte[size];
            Array.Copy(bytes, index, tmp, 0, size);
            return GetStructure<T>(tmp);
        }
    }
}
