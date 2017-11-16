using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Injector
{
	class Program
	{
#if WIN32
		const string procName = "ts3client_win32";
#else
		const string procName = "ts3client_win64";
#endif

		static void Main(string[] args)
		{
			DoHax();
			Console.ReadKey();
		}

		static void DoHax()
		{
			Process[] procs;
			do
			{
				procs = Process.GetProcessesByName(procName);
				if (procs.Length == 0)
				{
					Console.WriteLine("No Process found");
					System.Threading.Thread.Sleep(1000);
				}
			} while (procs.Length == 0);

			Process proc;
			if (procs.Length == 1)
			{
				proc = procs[0];
			}
			else
			{
				for (int i = 0; i < procs.Length; i++)
				{
					Console.WriteLine("[{0}] TeamSpeak 3 ({1})", i, procs[i].MainModule.FileVersionInfo.FileVersion);
				}

				Console.WriteLine("Select proc [0-{0}]", procs.Length - 1);
				int index = int.Parse(Console.ReadLine());
				proc = procs[index];
			}

			string res = DllInjector.Inject((uint)proc.Id, @"TS3Hook.dll");
			Console.WriteLine("Status = {0}", res ?? "OK");
			Console.WriteLine("Done");
		}
	}

    //[System.Security.Permissions.PrincipalPermission(System.Security.Permissions.SecurityAction.Demand, Role = @"BUILTIN\Administrators")]
    public static class DllInjector
	{
		[DllImport("kernel32.dll")]
		static extern int GetLastError();

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr OpenProcess(uint dwDesiredAccess, int bInheritHandle, uint dwProcessId);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern int CloseHandle(IntPtr hObject);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr GetModuleHandle(string lpModuleName);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, int lpNumberOfBytesWritten);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttribute, IntPtr dwStackSize, IntPtr lpStartAddress,
			IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

		public static string Inject(uint pToBeInjected, string sDllPath)
		{
			sDllPath = Path.GetFullPath(sDllPath);
			if (!File.Exists(sDllPath))
				return "Hook file not found";

			IntPtr hndProc = OpenProcess((0x2 | 0x8 | 0x10 | 0x20 | 0x400), 1, pToBeInjected);

			if (hndProc == IntPtr.Zero)
			{
				int errglc = GetLastError();
				return $"hndProc is null ({errglc.ToString("X")})";
			}

			IntPtr lpLLAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
			if (lpLLAddress == IntPtr.Zero)
			{
				return "lpLLAddress is null";
			}

			IntPtr lpAddress = VirtualAllocEx(hndProc, (IntPtr)null, (IntPtr)sDllPath.Length, (0x1000 | 0x2000), 0X40);
			if (lpAddress == IntPtr.Zero)
			{
				return "lpAddress is null";
			}

			byte[] bytes = Encoding.ASCII.GetBytes(sDllPath);

			int errcode;
			if ((errcode = WriteProcessMemory(hndProc, lpAddress, bytes, (uint)bytes.Length, 0)) == 0)
			{
				return $"WriteProcessMemory returned error: {errcode.ToString("X")}";
			}

			var ptr = CreateRemoteThread(hndProc, IntPtr.Zero, IntPtr.Zero, lpLLAddress, lpAddress, 0, IntPtr.Zero);
			if (ptr == IntPtr.Zero)
			{
				int errglc = GetLastError();
				return $"CreateRemoteThread returned error ({errglc.ToString("X")})";
			}

			CloseHandle(hndProc);

			return null;
		}
	}
}
