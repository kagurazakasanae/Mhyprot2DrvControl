using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MhyProt2Drv.Utils
{
	public struct rand_mt64
	{
		public ulong[] array;
		public ulong index;
		public ulong decodeKey;
	};
	class MT64
	{
		private static ulong RAND_MT64_ARRAY_LEN = 312;
		public rand_mt64 mt;

		public MT64()
		{
			mt = new rand_mt64();
			mt.array = new ulong[RAND_MT64_ARRAY_LEN];
		}
		public void rand_mt64_init(ulong seed)
		{
			ulong f = 0x5851f42d4c957f2d;
			ulong prev_value = seed;
			mt.index = RAND_MT64_ARRAY_LEN;
			mt.array[0] = prev_value;
			for (ulong i = 1; i < RAND_MT64_ARRAY_LEN; i += 1)
			{
				prev_value = i + f * (prev_value ^ (prev_value >> 62));
				mt.array[i] = prev_value;
			}
		}

		public ulong rand_mt64_get()
		{
			ulong m = 156;
			ulong n = RAND_MT64_ARRAY_LEN;
			ulong[] mag01 = new ulong[2] { 0, 0xB5026F5AA96619E9 };
			ulong UM = 0xFFFFFFFF80000000;
			ulong LM = 0x7FFFFFFF;
			ulong x;

			if (mt.index >= n)
			{
				ulong i;

				for (i = 0; i < n - m; i += 1)
				{
					x = (mt.array[i] & UM) | (mt.array[i + 1] & LM);
					mt.array[i] = mt.array[i + m] ^ (x >> 1) ^
						mag01[x & 0x1];
				}
				for (; i < n - 1; i += 1)
				{
					x = (mt.array[i] & UM) | (mt.array[i + 1] & LM);
					mt.array[i] = mt.array[i + (m - n)] ^ (x >> 1) ^
						mag01[x & 0x1];
				}
				x = (mt.array[i] & UM) | (mt.array[0] & LM);
				mt.array[i] = mt.array[m - 1] ^ (x >> 1) ^
					mag01[x & 0x1];

				mt.index = 0;
			}

			x = mt.array[mt.index];
			mt.index += 1;

			x ^= ((x >> 29) & 0x5555555555555555);
			x ^= ((x << 17) & 0x71D67FFFEDA60000);
			x ^= ((x << 37) & 0xFFF7EEE000000000);
			x ^= (x >> 43);

			return x;
		}
	}
}
