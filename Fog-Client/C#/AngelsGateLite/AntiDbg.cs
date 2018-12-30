using System;
using System.Collections.Generic;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32.SafeHandles;
using System.Text;

namespace System.Runtime.ExceptionServices {
    // AngelsGateLite by NIMIX3 (https://github.com/nimix3/AngelsGateLite) \\
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = false)]
	class HandleProcessCorruptedStateExceptionsAttribute : Attribute {
	}
}

namespace AntiDBG {
    // This Class Written by de4dot@gmail.com (https://github.com/0xd4d/antinet) \\
    public static class AntiManagedDebugger {
		[DllImport("kernel32", CharSet = CharSet.Auto)]
		static extern uint GetCurrentProcessId();

		[DllImport("kernel32")]
		static extern bool SetEvent(IntPtr hEvent);

		class Info {
			public int Debugger_pDebuggerRCThread;
			public int Debugger_pid;
			public int DebuggerRCThread_pDebugger;
			public int DebuggerRCThread_pDebuggerIPCControlBlock;
			public int DebuggerRCThread_shouldKeepLooping;
			public int DebuggerRCThread_hEvent1;
		}

		static readonly Info info_CLR20_x86 = new Info {
			Debugger_pDebuggerRCThread = 4,
			Debugger_pid = 8,
			DebuggerRCThread_pDebugger = 0x30,
			DebuggerRCThread_pDebuggerIPCControlBlock = 0x34,
			DebuggerRCThread_shouldKeepLooping = 0x3C,
			DebuggerRCThread_hEvent1 = 0x40,
		};

		static readonly Info info_CLR20_x64 = new Info {
			Debugger_pDebuggerRCThread = 8,
			Debugger_pid = 0x10,
			DebuggerRCThread_pDebugger = 0x58,
			DebuggerRCThread_pDebuggerIPCControlBlock = 0x60,
			DebuggerRCThread_shouldKeepLooping = 0x70,
			DebuggerRCThread_hEvent1 = 0x78,
		};

		static readonly Info info_CLR40_x86_1 = new Info {
			Debugger_pDebuggerRCThread = 8,
			Debugger_pid = 0xC,
			DebuggerRCThread_pDebugger = 0x34,
			DebuggerRCThread_pDebuggerIPCControlBlock = 0x38,
			DebuggerRCThread_shouldKeepLooping = 0x40,
			DebuggerRCThread_hEvent1 = 0x44,
		};

		static readonly Info info_CLR40_x86_2 = new Info {
			Debugger_pDebuggerRCThread = 8,
			Debugger_pid = 0xC,
			DebuggerRCThread_pDebugger = 0x30,
			DebuggerRCThread_pDebuggerIPCControlBlock = 0x34,
			DebuggerRCThread_shouldKeepLooping = 0x3C,
			DebuggerRCThread_hEvent1 = 0x40,
		};

		static readonly Info info_CLR40_x64 = new Info {
			Debugger_pDebuggerRCThread = 0x10,
			Debugger_pid = 0x18,
			DebuggerRCThread_pDebugger = 0x58,
			DebuggerRCThread_pDebuggerIPCControlBlock = 0x60,
			DebuggerRCThread_shouldKeepLooping = 0x70,
			DebuggerRCThread_hEvent1 = 0x78,
		};
		
		public unsafe static bool Initialize() {
			var info = GetInfo();
			var pDebuggerRCThread = FindDebuggerRCThreadAddress(info);
			if (pDebuggerRCThread == IntPtr.Zero)
				return false;
			byte* pDebuggerIPCControlBlock = (byte*)*(IntPtr*)((byte*)pDebuggerRCThread + info.DebuggerRCThread_pDebuggerIPCControlBlock);
			if (Environment.Version.Major == 2)
				pDebuggerIPCControlBlock = (byte*)*(IntPtr*)pDebuggerIPCControlBlock;
			*(uint*)pDebuggerIPCControlBlock = 0;
			*((byte*)pDebuggerRCThread + info.DebuggerRCThread_shouldKeepLooping) = 0;
			IntPtr hEvent = *(IntPtr*)((byte*)pDebuggerRCThread + info.DebuggerRCThread_hEvent1);
			SetEvent(hEvent);

			return true;
		}
		
		static Info GetInfo() {
			switch (Environment.Version.Major) {
			case 2: return IntPtr.Size == 4 ? info_CLR20_x86 : info_CLR20_x64;
			case 4:
				if (Environment.Version.Revision <= 17020)
					return IntPtr.Size == 4 ? info_CLR40_x86_1 : info_CLR40_x64;
				return IntPtr.Size == 4 ? info_CLR40_x86_2 : info_CLR40_x64;
			default: goto case 4;	// Assume CLR 4.0
			}
		}
		
		[HandleProcessCorruptedStateExceptions, SecurityCritical]	// Req'd on .NET 4.0
		static unsafe IntPtr FindDebuggerRCThreadAddress(Info info) {
			uint pid = GetCurrentProcessId();
			try {
				var peInfo = PEInfo.GetCLR();
				if (peInfo == null)
					return IntPtr.Zero;
				IntPtr sectionAddr;
				uint sectionSize;
				if (!peInfo.FindSection(".data", out sectionAddr, out sectionSize))
					return IntPtr.Zero;
				byte* p = (byte*)sectionAddr;
				byte* end = (byte*)sectionAddr + sectionSize;
				for (; p + IntPtr.Size <= end; p += IntPtr.Size) {
					IntPtr pDebugger = *(IntPtr*)p;
					if (pDebugger == IntPtr.Zero)
						continue;
					try {
						if (!PEInfo.IsAlignedPointer(pDebugger))
							continue;
						uint pid2 = *(uint*)((byte*)pDebugger + info.Debugger_pid);
						if (pid != pid2)
							continue;
						IntPtr pDebuggerRCThread = *(IntPtr*)((byte*)pDebugger + info.Debugger_pDebuggerRCThread);
						if (!PEInfo.IsAlignedPointer(pDebuggerRCThread))
							continue;
						IntPtr pDebugger2 = *(IntPtr*)((byte*)pDebuggerRCThread + info.DebuggerRCThread_pDebugger);
						if (pDebugger != pDebugger2)
							continue;
						return pDebuggerRCThread;
					}
					catch {
					}
				}
			}
			catch {
			}
			return IntPtr.Zero;
		}
	}
	
	public static class AntiManagedProfiler {
		static IProfilerDetector profilerDetector;

		interface IProfilerDetector {
			bool IsProfilerAttached { get; }
			bool WasProfilerAttached { get; }
			bool Initialize();
			void PreventActiveProfilerFromReceivingProfilingMessages();
		}

		class ProfilerDetectorCLR20 : IProfilerDetector {
			IntPtr profilerStatusFlag;

			bool wasAttached;

			public bool IsProfilerAttached {
				get {
					unsafe {
						if (profilerStatusFlag == IntPtr.Zero)
							return false;
						return (*(uint*)profilerStatusFlag & 6) != 0;
					}
				}
			}

			public bool WasProfilerAttached {
				get { return wasAttached; }
			}

			public bool Initialize() {
				bool result = FindProfilerStatus();
				wasAttached = IsProfilerAttached;
				return result;
			}

			unsafe bool FindProfilerStatus() {
				var addrCounts = new Dictionary<IntPtr, int>();
				try {
					var peInfo = PEInfo.GetCLR();
					if (peInfo == null)
						return false;
					IntPtr sectionAddr;
					uint sectionSize;
					if (!peInfo.FindSection(".text", out sectionAddr, out sectionSize))
						return false;
					const int MAX_COUNTS = 50;
					byte* p = (byte*)sectionAddr;
					byte* end = (byte*)sectionAddr + sectionSize;
					for (; p < end; p++) {
						IntPtr addr;
						if (*p == 0xF6 && p[1] == 0x05 && p[6] == 0x06) {
							if (IntPtr.Size == 4)
								addr = new IntPtr((void*)*(uint*)(p + 2));
							else
								addr = new IntPtr((void*)(p + 7 + *(int*)(p + 2)));
						}
						else
							continue;
						if (!PEInfo.IsAligned(addr, 4))
							continue;
						if (!peInfo.IsValidImageAddress(addr, 4))
							continue;
						try {
							*(uint*)addr = *(uint*)addr;
						}
						catch {
							continue;
						}
						int count = 0;
						addrCounts.TryGetValue(addr, out count);
						count++;
						addrCounts[addr] = count;
						if (count >= MAX_COUNTS)
							break;
					}
				}
				catch {
				}
				var foundAddr = GetMax(addrCounts, 5);
				if (foundAddr == IntPtr.Zero)
					return false;

				profilerStatusFlag = foundAddr;
				return true;
			}

			public unsafe void PreventActiveProfilerFromReceivingProfilingMessages() {
				if (profilerStatusFlag == IntPtr.Zero)
					return;
				*(uint*)profilerStatusFlag &= ~6U;
			}
		}

		class ProfilerDetectorCLR40 : IProfilerDetector {
			const uint PIPE_ACCESS_DUPLEX = 3;
			const uint PIPE_TYPE_MESSAGE = 4;
			const uint PIPE_READMODE_MESSAGE = 2;
			const uint FILE_FLAG_OVERLAPPED = 0x40000000;
			const uint GENERIC_READ = 0x80000000;
			const uint GENERIC_WRITE = 0x40000000;
			const uint OPEN_EXISTING = 3;
			const uint PAGE_EXECUTE_READWRITE = 0x40;

			[DllImport("kernel32", CharSet = CharSet.Auto)]
			static extern uint GetCurrentProcessId();

			[DllImport("kernel32", CharSet = CharSet.Auto)]
			static extern void Sleep(uint dwMilliseconds);

			[DllImport("kernel32", SetLastError = true)]
			static extern SafeFileHandle CreateNamedPipe(string lpName, uint dwOpenMode,
			   uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize,
			   uint nDefaultTimeOut, IntPtr lpSecurityAttributes);

			[DllImport("kernel32", SetLastError = true, CharSet = CharSet.Auto)]
			static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess,
			   uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
			   uint dwFlagsAndAttributes, IntPtr hTemplateFile);

			[DllImport("kernel32")]
			static extern bool VirtualProtect(IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

			const uint ConfigDWORDInfo_name = 0;
			static readonly uint ConfigDWORDInfo_defValue = (uint)IntPtr.Size;
			const string ProfAPIMaxWaitForTriggerMs_name = "ProfAPIMaxWaitForTriggerMs";

			IntPtr profilerControlBlock;
			SafeFileHandle profilerPipe;
			bool wasAttached;

			public bool IsProfilerAttached {
				get {
					unsafe {
						if (profilerControlBlock == IntPtr.Zero)
							return false;
						return *(uint*)((byte*)profilerControlBlock + IntPtr.Size + 4) != 0;
					}
				}
			}

			public bool WasProfilerAttached {
				get { return wasAttached; }
			}

			public bool Initialize() {
				bool result = FindProfilerControlBlock();
				result &= TakeOwnershipOfNamedPipe() || CreateNamedPipe();
				result &= PatchAttacherThreadProc();
				wasAttached = IsProfilerAttached;
				return result;
			}

			[HandleProcessCorruptedStateExceptions, SecurityCritical]	// Req'd on .NET 4.0
			unsafe bool TakeOwnershipOfNamedPipe() {
				try {
					if (CreateNamedPipe())
						return true;
					IntPtr threadingModeAddr = FindThreadingModeAddress();
					IntPtr timeOutOptionAddr = FindTimeOutOptionAddress();
					if (timeOutOptionAddr == IntPtr.Zero)
						return false;
					if (threadingModeAddr != IntPtr.Zero && *(uint*)threadingModeAddr == 2)
						*(uint*)threadingModeAddr = 1;
					FixTimeOutOption(timeOutOptionAddr);
					using (var hPipe = CreatePipeFileHandleWait()) {
						if (hPipe == null)
							return false;
						if (hPipe.IsInvalid)
							return false;
					}
					return CreateNamedPipeWait();
				}
				catch {
				}
				return false;
			}

			bool CreateNamedPipeWait() {
				int timeLeft = 100;
				const int waitTime = 5;
				while (timeLeft > 0) {
					if (CreateNamedPipe())
						return true;
					Sleep(waitTime);
					timeLeft -= waitTime;
				}
				return CreateNamedPipe();
			}

			[HandleProcessCorruptedStateExceptions, SecurityCritical]	// Req'd on .NET 4.0
			unsafe static void FixTimeOutOption(IntPtr timeOutOptionAddr) {
				if (timeOutOptionAddr == IntPtr.Zero)
					return;
				uint oldProtect;
				VirtualProtect(timeOutOptionAddr, (int)ConfigDWORDInfo_defValue + 4, PAGE_EXECUTE_READWRITE, out oldProtect);
				try {
					*(uint*)((byte*)timeOutOptionAddr + ConfigDWORDInfo_defValue) = 0;

				}
				finally {
					VirtualProtect(timeOutOptionAddr, (int)ConfigDWORDInfo_defValue + 4, oldProtect, out oldProtect);
				}
				char* name = *(char**)((byte*)timeOutOptionAddr + ConfigDWORDInfo_name);
				IntPtr nameAddr = new IntPtr(name);
				VirtualProtect(nameAddr, ProfAPIMaxWaitForTriggerMs_name.Length * 2, PAGE_EXECUTE_READWRITE, out oldProtect);
				try {
					var rand = new Random();
					for (int i = 0; i < ProfAPIMaxWaitForTriggerMs_name.Length; i++)
						name[i] = (char)rand.Next(1, ushort.MaxValue);
				}
				finally {
					VirtualProtect(nameAddr, IntPtr.Size, oldProtect, out oldProtect);
				}
			}

			SafeFileHandle CreatePipeFileHandleWait() {
				int timeLeft = 100;
				const int waitTime = 5;
				while (timeLeft > 0) {
					if (CreateNamedPipe())
						return null;
					var hFile = CreatePipeFileHandle();
					if (!hFile.IsInvalid)
						return hFile;
					Sleep(waitTime);
					timeLeft -= waitTime;
				}
				return CreatePipeFileHandle();
			}

			static SafeFileHandle CreatePipeFileHandle() {
				return CreateFile(GetPipeName(), GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, IntPtr.Zero);
			}

			static string GetPipeName() {
				return string.Format(@"\\.\pipe\CPFATP_{0}_v{1}.{2}.{3}",
							GetCurrentProcessId(), Environment.Version.Major,
							Environment.Version.Minor, Environment.Version.Build);
			}

			bool CreateNamedPipe() {
				if (profilerPipe != null && !profilerPipe.IsInvalid)
					return true;
				profilerPipe = CreateNamedPipe(GetPipeName(),
											FILE_FLAG_OVERLAPPED | PIPE_ACCESS_DUPLEX,
											PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
											1,
											0x24,
											0x338,
											1000,
											IntPtr.Zero);

				return !profilerPipe.IsInvalid;
			}

			[HandleProcessCorruptedStateExceptions, SecurityCritical]	// Req'd on .NET 4.0
			static unsafe IntPtr FindThreadingModeAddress() {
				try {
					var peInfo = PEInfo.GetCLR();
					if (peInfo == null)
						return IntPtr.Zero;
					IntPtr sectionAddr;
					uint sectionSize;
					if (!peInfo.FindSection(".text", out sectionAddr, out sectionSize))
						return IntPtr.Zero;
					byte* ptr = (byte*)sectionAddr;
					byte* end = (byte*)sectionAddr + sectionSize;
					for (; ptr < end; ptr++) {
						IntPtr addr;
						try {
							byte* p = ptr;
							if (*p != 0x83 || p[1] != 0x3D || p[6] != 2)
								continue;
							if (IntPtr.Size == 4)
								addr = new IntPtr((void*)*(uint*)(p + 2));
							else
								addr = new IntPtr((void*)(p + 7 + *(int*)(p + 2)));
							if (!PEInfo.IsAligned(addr, 4))
								continue;
							if (!peInfo.IsValidImageAddress(addr))
								continue;
							p += 7;
							if (*(uint*)addr < 1 || *(uint*)addr > 2)
								continue;
							*(uint*)addr = *(uint*)addr;
							if (!NextJz(ref p))
								continue;
							SkipRex(ref p);
							if (*p == 0x83 && p[2] == 0) {
								if ((uint)(p[1] - 0xE8) > 7)
									continue;
								p += 3;
							}
							else if (*p == 0x85) {
								int reg = (p[1] >> 3) & 7;
								int rm = p[1] & 7;
								if (reg != rm)
									continue;
								p += 2;
							}
							else
								continue;
							if (!NextJz(ref p))
								continue;
							if (!SkipDecReg(ref p))
								continue;
							if (!NextJz(ref p))
								continue;
							if (!SkipDecReg(ref p))
								continue;

							return addr;
						}
						catch {
						}
					}
				}
				catch {
				}
				return IntPtr.Zero;
			}

			[HandleProcessCorruptedStateExceptions, SecurityCritical]	// Req'd on .NET 4.0
			static unsafe IntPtr FindTimeOutOptionAddress() {
				try {
					var peInfo = PEInfo.GetCLR();
					if (peInfo == null)
						return IntPtr.Zero;
					IntPtr sectionAddr;
					uint sectionSize;
					if (!peInfo.FindSection(".rdata", out sectionAddr, out sectionSize) &&
						!peInfo.FindSection(".text", out sectionAddr, out sectionSize))
						return IntPtr.Zero;
					byte* p = (byte*)sectionAddr;
					byte* end = (byte*)sectionAddr + sectionSize;
					for (; p < end; p++) {
						try {
							char* name = *(char**)(p + ConfigDWORDInfo_name);
							if (!PEInfo.IsAligned(new IntPtr(name), 2))
								continue;
							if (!peInfo.IsValidImageAddress(name))
								continue;

							if (!Equals(name, ProfAPIMaxWaitForTriggerMs_name))
								continue;

							return new IntPtr(p);
						}
						catch {
						}
					}
				}
				catch {
				}
				return IntPtr.Zero;
			}

			unsafe static bool Equals(char* s1, string s2) {
				for (int i = 0; i < s2.Length; i++) {
					if (char.ToUpperInvariant(s1[i]) != char.ToUpperInvariant(s2[i]))
						return false;
				}
				return s1[s2.Length] == 0;
			}

			unsafe static void SkipRex(ref byte* p) {
				if (IntPtr.Size != 8)
					return;
				if (*p >= 0x48 && *p <= 0x4F)
					p++;
			}

			unsafe static bool SkipDecReg(ref byte* p) {
				SkipRex(ref p);
				if (IntPtr.Size == 4 && *p >= 0x48 && *p <= 0x4F)
					p++;
				else if (*p == 0xFF && p[1] >= 0xC8 && p[1] <= 0xCF)
					p += 2;
				else
					return false;
				return true;
			}
			
			unsafe static bool NextJz(ref byte* p) {
				if (*p == 0x74) {
					p += 2;
					return true;
				}
				if (*p == 0x0F && p[1] == 0x84) {
					p += 6;
					return true;
				}
				return false;
			}

			[HandleProcessCorruptedStateExceptions, SecurityCritical]	// Req'd on .NET 4.0
			unsafe bool PatchAttacherThreadProc() {
				IntPtr threadProc = FindAttacherThreadProc();
				if (threadProc == IntPtr.Zero)
					return false;
				byte* p = (byte*)threadProc;
				uint oldProtect;
				VirtualProtect(new IntPtr(p), 5, PAGE_EXECUTE_READWRITE, out oldProtect);
				try {
					if (IntPtr.Size == 4) {
						p[0] = 0x33; p[1] = 0xC0;
						p[2] = 0xC2; p[3] = 0x04; p[4] = 0x00;
					}
					else {
						p[0] = 0x33; p[1] = 0xC0;
						p[2] = 0xC3;
					}
				}
				finally {
					VirtualProtect(new IntPtr(p), 5, oldProtect, out oldProtect);
				}
				return true;
			}

			[HandleProcessCorruptedStateExceptions, SecurityCritical]	// Req'd on .NET 4.0
			unsafe IntPtr FindAttacherThreadProc() {
				try {
					var peInfo = PEInfo.GetCLR();
					if (peInfo == null)
						return IntPtr.Zero;
					IntPtr sectionAddr;
					uint sectionSize;
					if (!peInfo.FindSection(".text", out sectionAddr, out sectionSize))
						return IntPtr.Zero;
					byte* p = (byte*)sectionAddr;
					byte* start = p;
					byte* end = (byte*)sectionAddr + sectionSize;
					if (IntPtr.Size == 4) {
						for (; p < end; p++) {
							byte push = *p;
							if (push < 0x50 || push > 0x57)
								continue;
							if (p[1] != push || p[2] != push || p[8] != push || p[9] != push)
								continue;
							if (p[3] != 0x68)
								continue;
							if (p[10] != 0xFF || p[11] != 0x15)
								continue;
							IntPtr threadProc = new IntPtr((void*)*(uint*)(p + 4));
							if (!CheckThreadProc(start, end, threadProc))
								continue;
							return threadProc;
						}
					}
					else {
						for (; p < end; p++) {
							if (*p != 0x45 && p[1] != 0x33 && p[2] != 0xC9)
								continue;
							if (p[3] != 0x4C && p[4] != 0x8D && p[5] != 0x05)
								continue;
							if (p[10] != 0x33 && p[11] != 0xD2)
								continue;
							if (p[12] != 0x33 && p[13] != 0xC9)
								continue;
							if (p[14] != 0xFF && p[15] != 0x15)
								continue;
							IntPtr threadProc = new IntPtr(p + 10 + *(int*)(p + 6));
							if (!CheckThreadProc(start, end, threadProc))
								continue;
							return threadProc;
						}
					}
				}
				catch {
				}
				return IntPtr.Zero;
			}

			[HandleProcessCorruptedStateExceptions, SecurityCritical]	// Req'd on .NET 4.0
			unsafe static bool CheckThreadProc(byte* codeStart, byte* codeEnd, IntPtr threadProc) {
				try {
					byte* p = (byte*)threadProc;
					if (p < codeStart || p >= codeEnd)
						return false;
					for (int i = 0; i < 0x20; i++) {
						if (*(uint*)(p + i) == 0x4000)
							return true;
					}
				}
				catch {
				}
				return false;
			}

			[HandleProcessCorruptedStateExceptions, SecurityCritical]	// Req'd on .NET 4.0
			unsafe bool FindProfilerControlBlock() {
				var addrCounts = new Dictionary<IntPtr, int>();
				try {
					var peInfo = PEInfo.GetCLR();
					if (peInfo == null)
						return false;
					IntPtr sectionAddr;
					uint sectionSize;
					if (!peInfo.FindSection(".text", out sectionAddr, out sectionSize))
						return false;
					const int MAX_COUNTS = 50;
					byte* p = (byte*)sectionAddr;
					byte* end = (byte*)sectionAddr + sectionSize;
					for (; p < end; p++) {
						IntPtr addr;
						if (*p == 0xA1 && p[5] == 0x83 && p[6] == 0xF8 && p[7] == 0x04) {
							if (IntPtr.Size == 4)
								addr = new IntPtr((void*)*(uint*)(p + 1));
							else
								addr = new IntPtr((void*)(p + 5 + *(int*)(p + 1)));
						}
						else if (*p == 0x8B && p[1] == 0x05 && p[6] == 0x83 && p[7] == 0xF8 && p[8] == 0x04) {
							if (IntPtr.Size == 4)
								addr = new IntPtr((void*)*(uint*)(p + 2));
							else
								addr = new IntPtr((void*)(p + 6 + *(int*)(p + 2)));
						}
						else if (*p == 0x83 && p[1] == 0x3D && p[6] == 0x04) {
							if (IntPtr.Size == 4)
								addr = new IntPtr((void*)*(uint*)(p + 2));
							else
								addr = new IntPtr((void*)(p + 7 + *(int*)(p + 2)));
						}
						else
							continue;

						if (!PEInfo.IsAligned(addr, 4))
							continue;
						if (!peInfo.IsValidImageAddress(addr, 4))
							continue;
						try {
							if (*(uint*)addr > 4)
								continue;
							*(uint*)addr = *(uint*)addr;
						}
						catch {
							continue;
						}
						int count = 0;
						addrCounts.TryGetValue(addr, out count);
						count++;
						addrCounts[addr] = count;
						if (count >= MAX_COUNTS)
							break;
					}
				}
				catch {
				}
				var foundAddr = GetMax(addrCounts, 5);
				if (foundAddr == IntPtr.Zero)
					return false;
				profilerControlBlock = new IntPtr((byte*)foundAddr - (IntPtr.Size + 4));
				return true;
			}
			public unsafe void PreventActiveProfilerFromReceivingProfilingMessages() {
				if (profilerControlBlock == IntPtr.Zero)
					return;
				*(uint*)((byte*)profilerControlBlock + IntPtr.Size + 4) = 0;
			}
		}

		public static bool IsProfilerAttached {
			[HandleProcessCorruptedStateExceptions, SecurityCritical]	// Req'd on .NET 4.0
			get {
				try {
					if (profilerDetector == null)
						return false;
					return profilerDetector.IsProfilerAttached;
				}
				catch {
				}
				return false;
			}
		}

		public static bool WasProfilerAttached {
			[HandleProcessCorruptedStateExceptions, SecurityCritical]	// Req'd on .NET 4.0
			get {
				try {
					if (profilerDetector == null)
						return false;
					return profilerDetector.WasProfilerAttached;
				}
				catch {
				}
				return false;
			}
		}

		public static bool Initialize() {
			profilerDetector = CreateProfilerDetector();
			return profilerDetector.Initialize();
		}

		static IProfilerDetector CreateProfilerDetector() {
			if (Environment.Version.Major == 2)
				return new ProfilerDetectorCLR20();
			return new ProfilerDetectorCLR40();
		}

		public static void PreventActiveProfilerFromReceivingProfilingMessages() {
			if (profilerDetector == null)
				return;
			profilerDetector.PreventActiveProfilerFromReceivingProfilingMessages();
		}

		static IntPtr GetMax(Dictionary<IntPtr, int> addresses, int minCount) {
			IntPtr foundAddr = IntPtr.Zero;
			int maxCount = 0;
			foreach (var kv in addresses) {
				if (foundAddr == IntPtr.Zero || maxCount < kv.Value) {
					foundAddr = kv.Key;
					maxCount = kv.Value;
				}
			}
			return maxCount >= minCount ? foundAddr : IntPtr.Zero;
		}
	}
	
		class PEInfo {
		IntPtr imageBase;
		IntPtr imageEnd;
		IntPtr sectionsAddr;
		int numSects;

		[DllImport("kernel32", CharSet = CharSet.Auto)]
		static extern IntPtr GetModuleHandle(string name);

		public static PEInfo GetCLR() {
			var clrAddr = GetCLRAddress();
			if (clrAddr == IntPtr.Zero)
				return null;
			return new PEInfo(clrAddr);
		}

		static IntPtr GetCLRAddress() {
			if (Environment.Version.Major == 2)
				return GetModuleHandle("mscorwks");
			return GetModuleHandle("clr");
		}

		public PEInfo(IntPtr addr) {
			this.imageBase = addr;
			Initialize();
		}

		unsafe void Initialize() {
			byte* p = (byte*)imageBase;
			p += *(uint*)(p + 0x3C);
			p += 4 + 2;
			numSects = *(ushort*)p;
			p += 2 + 0x10;
			bool is32 = *(ushort*)p == 0x010B;
			uint sizeOfImage = *(uint*)(p + 0x38);
			imageEnd = new IntPtr((byte*)imageBase + sizeOfImage);
			p += is32 ? 0x60 : 0x70;
			p += 0x10 * 8;
			sectionsAddr = new IntPtr(p);
		}

		public unsafe bool IsValidImageAddress(IntPtr addr) {
			return IsValidImageAddress((void*)addr, 0);
		}

		public unsafe bool IsValidImageAddress(IntPtr addr, uint size) {
			return IsValidImageAddress((void*)addr, size);
		}

		public unsafe bool IsValidImageAddress(void* addr) {
			return IsValidImageAddress(addr, 0);
		}

		public unsafe bool IsValidImageAddress(void* addr, uint size) {
			if (addr < (void*)imageBase)
				return false;
			if (addr >= (void*)imageEnd)
				return false;
			if (size != 0) {
				if ((byte*)addr + size < (void*)addr)
					return false;
				if ((byte*)addr + size > (void*)imageEnd)
					return false;
			}
			return true;
		}
		
		public unsafe bool FindSection(string name, out IntPtr sectionStart, out uint sectionSize) {
			var nameBytes = Encoding.UTF8.GetBytes(name + "\0\0\0\0\0\0\0\0");
			for (int i = 0; i < numSects; i++) {
				byte* p = (byte*)sectionsAddr + i * 0x28;
				if (!CompareSectionName(p, nameBytes))
					continue;
				sectionStart = new IntPtr((byte*)imageBase + *(uint*)(p + 12));
				sectionSize = Math.Max(*(uint*)(p + 8), *(uint*)(p + 16));
				return true;
			}
			sectionStart = IntPtr.Zero;
			sectionSize = 0;
			return false;
		}

		static unsafe bool CompareSectionName(byte* sectionName, byte[] nameBytes) {
			for (int i = 0; i < 8; i++) {
				if (*sectionName != nameBytes[i])
					return false;
				sectionName++;
			}
			return true;
		}

		public static bool IsAlignedPointer(IntPtr addr) {
			return ((int)addr.ToInt64() & (IntPtr.Size - 1)) == 0;
		}

		public static bool IsAligned(IntPtr addr, uint alignment) {
			return ((uint)addr.ToInt64() & (alignment - 1)) == 0;
		}

		public override string ToString() {
			return string.Format("{0:X8} - {1:X8}", (ulong)imageBase.ToInt64(), (ulong)imageEnd.ToInt64());
		}
	}

}
