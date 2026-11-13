using System;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;

public static class Harness
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr process, IntPtr address, UIntPtr size, uint type, uint protect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr process, IntPtr address, byte[] buffer, UIntPtr size, out UIntPtr written);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, int size, IntPtr read);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetModuleHandleA(string name);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern IntPtr GetProcAddress(IntPtr module, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateRemoteThread(IntPtr process, IntPtr attributes, UIntPtr stackSize, IntPtr start, IntPtr parameter, uint flags, out uint threadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeThread(IntPtr thread, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);
[DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualFreeEx(IntPtr process, IntPtr address, UIntPtr size, uint release);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateToolhelp32Snapshot(uint flags, int pid);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool Process32FirstW(IntPtr snapshot, ref PROCESSENTRY32W entry);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool Process32NextW(IntPtr snapshot, ref PROCESSENTRY32W entry);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool Module32FirstW(IntPtr snapshot, ref MODULEENTRY32W entry);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool Module32NextW(IntPtr snapshot, ref MODULEENTRY32W entry);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct MODULEENTRY32W
    {
        public uint dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlblcntUsage;
        public uint ProccntUsage;
        public IntPtr modBaseAddr;
        public uint modBaseSize;
        public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExePath;
    }

    static void EnumerateQqProcesses()
    {
        const uint TH32CS_SNAPPROCESS = 0x00000002;
        const uint TH32CS_SNAPMODULE = 0x00000008;
        const uint TH32CS_SNAPMODULE32 = 0x00000010;

        IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == new IntPtr(-1))
        {
            Console.WriteLine("SNAPSHOT_FAIL " + Marshal.GetLastWin32Error());
            return;
        }

        PROCESSENTRY32W pe = new PROCESSENTRY32W();
        pe.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32W));

        int count = 0;
        if (Process32FirstW(snapshot, ref pe))
        {
            do
            {
                string name = pe.szExeFile ?? "";
                if (name.IndexOf("QQ", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    continue;
                }

                Console.WriteLine("PROC pid=" + pe.th32ProcessID + " name=" + name + " parent=" + pe.th32ParentProcessID);
                ++count;

                IntPtr modSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                                          (int)pe.th32ProcessID);
                if (modSnap != new IntPtr(-1))
                {
                    MODULEENTRY32W me = new MODULEENTRY32W();
                    me.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32W));

                    if (Module32FirstW(modSnap, ref me))
                    {
                        do
                        {
                            string mod = me.szModule ?? "";
                            if (mod.IndexOf("wrapper", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                mod.IndexOf("major", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                Console.WriteLine("  MOD " + mod + " base=0x" + me.modBaseAddr.ToInt64().ToString("X") +
                                                  " size=" + me.modBaseSize);
                            }
                        } while (Module32NextW(modSnap, ref me));
                    }

                    CloseHandle(modSnap);
                }
            } while (Process32NextW(snapshot, ref pe));
        }

        CloseHandle(snapshot);
        Console.WriteLine("TOTAL_QQ_PROCS " + count);
    }

    public static int Main(string[] args)
    {
        int pid = 0;
        string dllPath = null;
        bool enumOnly = false;

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "-pid" && i + 1 < args.Length) { int.TryParse(args[++i], out pid); }
            else if (args[i] == "-dll" && i + 1 < args.Length) { dllPath = args[++i]; }
            else if (args[i] == "-enum") { enumOnly = true; }
        }

        if (enumOnly)
        {
            EnumerateQqProcesses();
            return 0;
        }

        if (pid <= 0 || string.IsNullOrEmpty(dllPath))
        {
            Console.WriteLine("USAGE Harness.exe -pid <pid> -dll <path> | -enum");
            return 100;
        }

        Console.WriteLine("HARNESS_START pid=" + pid + " dll=" + dllPath);

        Stopwatch total = Stopwatch.StartNew();
        Stopwatch stage = Stopwatch.StartNew();

        int injected = Inject(pid, dllPath);
        Console.WriteLine("STAGE inject elapsed=" + stage.ElapsedMilliseconds + "ms result=" + injected);
        if (injected != 0)
        {
            Console.WriteLine("INJECT_FAIL " + injected);
            return injected;
        }

        Console.WriteLine("INJECTED_OK");

        stage.Restart();
        NamedPipeClientStream pipe = null;
        for (int attempt = 0; attempt < 60; attempt++)
        {
            try
            {
                NamedPipeClientStream candidate = new NamedPipeClientStream(
                    ".", "mojo." + pid + ".control", PipeDirection.InOut);
                candidate.Connect(500);
                pipe = candidate;
                break;
            }
            catch
            {
                System.Threading.Thread.Sleep(200);
            }
        }
        Console.WriteLine("STAGE pipe_connect elapsed=" + stage.ElapsedMilliseconds + "ms");

        if (pipe == null)
        {
            Console.WriteLine("PIPE_CONNECT_FAIL total=" + total.ElapsedMilliseconds + "ms");
            return 20;
        }

        Console.WriteLine("PIPE_CONNECTED");

        byte[] hello = ReadFrame(pipe, 5000);
        if (hello == null)
        {
            Console.WriteLine("HELLO_TIMEOUT");
            return 21;
        }

        uint helloMagic = BitConverter.ToUInt32(hello, 0);
        ushort helloOp = BitConverter.ToUInt16(hello, 6);
        ulong helloPid = BitConverter.ToUInt64(hello, 32);
        Console.WriteLine("HELLO magic=0x" + helloMagic.ToString("X8") + " op=" + helloOp + " pid=" + helloPid);

        string[] names = new string[]
        {
            "SendSSORequestInternal",
            "OnLoginSuccess",
            "LoginRequest"
        };
        foreach (string name in names)
        {
            Stopwatch queryWatch = Stopwatch.StartNew();
            Query(pipe, name, queryWatch);
        }

        Stopwatch hookWatch = Stopwatch.StartNew();
        HookCommand(pipe, 26, "SendSSORequestInternal");
        Console.WriteLine("HOOK_INSTALL elapsed=" + hookWatch.ElapsedMilliseconds + "ms");
        HookCommand(pipe, 26, "LoginRequest");
        Console.WriteLine("HOOK_INSTALL_LOGIN elapsed=" + hookWatch.ElapsedMilliseconds + "ms");
        HookCommand(pipe, 26, "OnRecvMsg");
        Console.WriteLine("HOOK_INSTALL_RECV elapsed=" + hookWatch.ElapsedMilliseconds + "ms");
        System.Threading.Thread.Sleep(500);
        HookCommand(pipe, 27, "");
        Console.WriteLine("HOOK_STATE elapsed=" + hookWatch.ElapsedMilliseconds + "ms");

        HookCommand(pipe, 28, "");
        Console.WriteLine("INVOKE_CHECK elapsed=" + hookWatch.ElapsedMilliseconds + "ms");

        HookCommand(pipe, 29, "");
        Console.WriteLine("RECV_TEST elapsed=" + hookWatch.ElapsedMilliseconds + "ms");

        HookCommand(pipe, 30, "");
        Console.WriteLine("DRYRUN_CHECK elapsed=" + hookWatch.ElapsedMilliseconds + "ms");

        HookCommand(pipe, 31, "");
        Console.WriteLine("CAPTURE_TEST elapsed=" + hookWatch.ElapsedMilliseconds + "ms");
        ReadMemCommand(pipe, sendSsoTarget, 16);
        Console.WriteLine("READMEM_TEST elapsed=" + hookWatch.ElapsedMilliseconds + "ms");
        SendRequestTest(pipe, "MessageSvc.PbSendMsg", new byte[] { 0x08, 0x01, 0x12, 0x03, 0x61, 0x62, 0x63 });
        Console.WriteLine("SENDREQ_TEST elapsed=" + hookWatch.ElapsedMilliseconds + "ms");
        IdentityHintTest(pipe, 10001);
        Console.WriteLine("IDENTHINT_TEST elapsed=" + hookWatch.ElapsedMilliseconds + "ms");
        System.Threading.Thread.Sleep(500);
        Console.WriteLine("RECV_DRAIN " + DrainRecv(pipe, hookWatch, pid));

        System.Threading.Thread.Sleep(2000);
        HookCommand(pipe, 27, "");
        Console.WriteLine("HOOK_STATE_AFTER elapsed=" + hookWatch.ElapsedMilliseconds + "ms");
        for (int round = 1; round <= 8; round++)
        {
            System.Threading.Thread.Sleep(3000);
            HookCommand(pipe, 27, "");
            Console.WriteLine("HOOK_POLL round=" + round + " elapsed=" + hookWatch.ElapsedMilliseconds + "ms");
        }
        HookCommand(pipe, 33, "");
        Console.WriteLine("INJECT_RECV elapsed=" + hookWatch.ElapsedMilliseconds + "ms");
        System.Threading.Thread.Sleep(1200);
        Console.WriteLine("AUTO_RECV_DRAIN " + DrainRecv(pipe, hookWatch, pid));
        HookCommand(pipe, 34, "");
        Console.WriteLine("INJECT_LOGIN elapsed=" + hookWatch.ElapsedMilliseconds + "ms");
        System.Threading.Thread.Sleep(1200);
        Console.WriteLine("AUTO_LOGIN_DRAIN " + DrainRecv(pipe, hookWatch, pid));
        HookCommand(pipe, 36, "");
        Console.WriteLine("INJECT_SEND elapsed=" + hookWatch.ElapsedMilliseconds + "ms");
        SendRequestTest(pipe, "MessageSvc.PbSendMsg", new byte[] { 0x08, 0x02, 0x12, 0x03, 0x78, 0x79, 0x7A });
        Console.WriteLine("SENDREQ_SYNTH elapsed=" + hookWatch.ElapsedMilliseconds + "ms");
        HookCommand(pipe, 37, "");
        Console.WriteLine("RESET_SEND elapsed=" + hookWatch.ElapsedMilliseconds + "ms");
        HookCommand(pipe, 35, "");
        Console.WriteLine("RESET_LOGIN elapsed=" + hookWatch.ElapsedMilliseconds + "ms");
        pipe.Close();
        CallPrepareUnload(pid, dllPath);
        Console.WriteLine("STAGE total elapsed=" + total.ElapsedMilliseconds + "ms");
        Console.WriteLine("HARNESS_DONE");
        return 0;
    }

    static ulong sendSsoTarget = 0;

    static void ReadMemCommand(NamedPipeClientStream pipe, ulong address, uint length)
    {
        byte[] frame = new byte[52];
        BitConverter.GetBytes(0x31504851u).CopyTo(frame, 0);
        BitConverter.GetBytes((ushort)1).CopyTo(frame, 4);
        BitConverter.GetBytes((ushort)32).CopyTo(frame, 6);
        BitConverter.GetBytes(400u).CopyTo(frame, 8);
        BitConverter.GetBytes(0).CopyTo(frame, 12);
        BitConverter.GetBytes(0u).CopyTo(frame, 16);
        BitConverter.GetBytes(8u).CopyTo(frame, 20);
        BitConverter.GetBytes(0u).CopyTo(frame, 24);
        BitConverter.GetBytes(4u).CopyTo(frame, 28);
        BitConverter.GetBytes(0ul).CopyTo(frame, 32);
        BitConverter.GetBytes(address).CopyTo(frame, 40);
        BitConverter.GetBytes(length).CopyTo(frame, 48);

        pipe.Write(frame, 0, frame.Length);
        pipe.Flush();

        byte[] reply = ReadFrame(pipe, 15000);
        if (reply == null)
        {
            Console.WriteLine("READMEM -> TIMEOUT");
            return;
        }

        int status = BitConverter.ToInt32(reply, 12);
        uint bodyLen = BitConverter.ToUInt32(reply, 28);
        string hex = "";
        string ascii = "";
        for (int i = 0; i < bodyLen && i < 32; i++)
        {
            byte b = reply[40 + i];
            hex += b.ToString("X2");
            ascii += (b >= 32 && b < 127) ? (char)b : '.';
        }
        Console.WriteLine("READMEM status=" + status + " addr=0x" + address.ToString("X") + " len=" + bodyLen);
        if (hex.Length > 0)
        {
            Console.WriteLine("  HEX " + hex);
            Console.WriteLine("  ASCII " + ascii);
        }
    }

    static void IdentityHintTest(NamedPipeClientStream pipe, ulong uin)
    {
        byte[] frame = new byte[40];
        BitConverter.GetBytes(0x31504851u).CopyTo(frame, 0);
        BitConverter.GetBytes((ushort)1).CopyTo(frame, 4);
        BitConverter.GetBytes((ushort)17).CopyTo(frame, 6);
        BitConverter.GetBytes(500u).CopyTo(frame, 8);
        BitConverter.GetBytes(0).CopyTo(frame, 12);
        BitConverter.GetBytes(0u).CopyTo(frame, 16);
        BitConverter.GetBytes(0u).CopyTo(frame, 20);
        BitConverter.GetBytes(0u).CopyTo(frame, 24);
        BitConverter.GetBytes(0u).CopyTo(frame, 28);
        BitConverter.GetBytes(uin).CopyTo(frame, 32);

        pipe.Write(frame, 0, frame.Length);
        pipe.Flush();

        byte[] ack = ReadFrame(pipe, 15000);
        if (ack == null)
        {
            Console.WriteLine("IDENTHINT -> TIMEOUT");
            return;
        }

        ushort ackOp = BitConverter.ToUInt16(ack, 6);
        uint ackReq = BitConverter.ToUInt32(ack, 8);
        int ackStatus = BitConverter.ToInt32(ack, 12);
        Console.WriteLine("IDENTHINT ack op=" + ackOp + " req=" + ackReq + " status=" + ackStatus);
    }

    static void SendRequestTest(NamedPipeClientStream pipe, string cmd, byte[] body)
    {
        byte[] cmdBytes = Encoding.ASCII.GetBytes(cmd);
        int total = 40 + cmdBytes.Length + body.Length;
        byte[] frame = new byte[total];

        BitConverter.GetBytes(0x31504851u).CopyTo(frame, 0);
        BitConverter.GetBytes((ushort)1).CopyTo(frame, 4);
        BitConverter.GetBytes((ushort)2).CopyTo(frame, 6);
        BitConverter.GetBytes(300u).CopyTo(frame, 8);
        BitConverter.GetBytes(0).CopyTo(frame, 12);
        BitConverter.GetBytes(1u).CopyTo(frame, 16);
        BitConverter.GetBytes((uint)cmdBytes.Length).CopyTo(frame, 20);
        BitConverter.GetBytes(0u).CopyTo(frame, 24);
        BitConverter.GetBytes((uint)body.Length).CopyTo(frame, 28);
        BitConverter.GetBytes(0ul).CopyTo(frame, 32);
        cmdBytes.CopyTo(frame, 40);
        body.CopyTo(frame, 40 + cmdBytes.Length);

        pipe.Write(frame, 0, frame.Length);
        pipe.Flush();

        byte[] ack = ReadFrame(pipe, 15000);
        if (ack == null)
        {
            Console.WriteLine("SENDREQ -> ACK TIMEOUT");
            return;
        }

        ushort ackOp = BitConverter.ToUInt16(ack, 6);
        int ackStatus = BitConverter.ToInt32(ack, 12);
        string ackMsg = ack.Length > 40 ? Encoding.ASCII.GetString(ack, 40, ack.Length - 40) : "";
        Console.WriteLine("SENDREQ ack op=" + ackOp + " status=" + ackStatus + " msg=" + ackMsg);

        if (ackStatus != 0)
        {
            Console.WriteLine("SENDREQ skipped reply (ack failed)");
            return;
        }

        byte[] preply = ReadFrame(pipe, 15000);
        if (preply == null)
        {
            Console.WriteLine("SENDREQ -> REPLY TIMEOUT");
            return;
        }

        ushort replyOp = BitConverter.ToUInt16(preply, 6);
        int replyStatus = BitConverter.ToInt32(preply, 12);
        Console.WriteLine("SENDREQ reply op=" + replyOp + " status=" + replyStatus);
    }

    static void HookCommand(NamedPipeClientStream pipe, ushort op, string name)
    {
        byte[] nameBytes = Encoding.ASCII.GetBytes(name);
        int total = 40 + nameBytes.Length;
        byte[] frame = new byte[total];

        BitConverter.GetBytes(0x31504851u).CopyTo(frame, 0);
        BitConverter.GetBytes((ushort)1).CopyTo(frame, 4);
        BitConverter.GetBytes(op).CopyTo(frame, 6);
        BitConverter.GetBytes(200u).CopyTo(frame, 8);
        BitConverter.GetBytes(0).CopyTo(frame, 12);
        BitConverter.GetBytes(0u).CopyTo(frame, 16);
        BitConverter.GetBytes((uint)nameBytes.Length).CopyTo(frame, 20);
        BitConverter.GetBytes(0u).CopyTo(frame, 24);
        BitConverter.GetBytes(0u).CopyTo(frame, 28);
        BitConverter.GetBytes(0ul).CopyTo(frame, 32);
        nameBytes.CopyTo(frame, 40);

        pipe.Write(frame, 0, frame.Length);
        pipe.Flush();

        byte[] reply = ReadFrame(pipe, 15000);
        if (reply == null)
        {
            Console.WriteLine("HOOK op=" + op + " -> TIMEOUT");
            return;
        }

        int status = BitConverter.ToInt32(reply, 12);
        ulong target = BitConverter.ToUInt64(reply, 32);
        string detail = "";
        if (reply.Length > 40)
        {
            detail = Encoding.ASCII.GetString(reply, 40, reply.Length - 40);
        }

        Console.WriteLine("HOOK op=" + op + " status=" + status + " target=0x" + target.ToString("X"));
        if (detail.Length > 0)
        {
            Console.WriteLine("  DETAIL " + detail);
        }
    }
    static void Query(NamedPipeClientStream pipe, string name, Stopwatch watch)
    {
        byte[] nameBytes = Encoding.ASCII.GetBytes(name);
        int total = 40 + nameBytes.Length;
        byte[] frame = new byte[total];

        BitConverter.GetBytes(0x31504851u).CopyTo(frame, 0);
        BitConverter.GetBytes((ushort)1).CopyTo(frame, 4);
        BitConverter.GetBytes((ushort)25).CopyTo(frame, 6);
        BitConverter.GetBytes(100u).CopyTo(frame, 8);
        BitConverter.GetBytes(0).CopyTo(frame, 12);
        BitConverter.GetBytes(0u).CopyTo(frame, 16);
        BitConverter.GetBytes((uint)nameBytes.Length).CopyTo(frame, 20);
        BitConverter.GetBytes(0u).CopyTo(frame, 24);
        BitConverter.GetBytes(0u).CopyTo(frame, 28);
        BitConverter.GetBytes(0ul).CopyTo(frame, 32);
        nameBytes.CopyTo(frame, 40);

        pipe.Write(frame, 0, frame.Length);
        pipe.Flush();

        byte[] reply = ReadFrame(pipe, 30000);
        if (reply == null)
        {
            Console.WriteLine("LOCATE " + name + " -> TIMEOUT");
            return;
        }

        int status = BitConverter.ToInt32(reply, 12);
        uint error = BitConverter.ToUInt32(reply, 16);
        ulong target = BitConverter.ToUInt64(reply, 32);

        string detail = "";
        if (reply.Length > 40)
        {
            detail = Encoding.ASCII.GetString(reply, 40, reply.Length - 40);
        }

        Console.WriteLine("LOCATE " + name + " -> status=" + status + " target=0x" + target.ToString("X") + " error=" + error + " elapsed=" + watch.ElapsedMilliseconds + "ms");
        if (name == "SendSSORequestInternal" && status == 1 && target != 0)
        {
            sendSsoTarget = target;
        }
        if (detail.Length > 0)
        {
            Console.WriteLine("  DETAIL " + detail);
        }
    }

    static string DrainRecv(NamedPipeClientStream controlPipe, Stopwatch watch, int qqPid)
    {
        try
        {
            NamedPipeClientStream recv = new NamedPipeClientStream(
                ".", "mojo." + qqPid + ".recv", PipeDirection.InOut);
            recv.Connect(5000);
            byte[] hello = ReadFrame(recv, 3000);
            if (hello == null)
            {
                recv.Close();
                return "hello_timeout";
            }
            byte[] frame = ReadFrame(recv, 2000);
            if (frame == null)
            {
                recv.Close();
                return "no_packet";
            }
            ushort op = BitConverter.ToUInt16(frame, 6);
            ulong seq = BitConverter.ToUInt64(frame, 32);
            uint cmdLen = BitConverter.ToUInt32(frame, 20);
            uint msgLen = BitConverter.ToUInt32(frame, 24);
            uint bodyLen = BitConverter.ToUInt32(frame, 28);
            string cmd = cmdLen > 0 ? Encoding.ASCII.GetString(frame, 40, (int)cmdLen) : "";
            string uin = msgLen > 0 ? Encoding.ASCII.GetString(frame, 40 + (int)cmdLen, (int)msgLen) : "";
            string bodyHex = "";
            if (bodyLen > 0)
            {
                for (int i = 0; i < bodyLen && i < 8; i++)
                {
                    bodyHex += frame[40 + cmdLen + msgLen + i].ToString("X2");
                }
            }
            recv.Close();
            return "op=" + op + " seq=" + seq + " cmd=" + cmd + " uin=" + uin + " body=" + bodyHex;
        }
        catch (Exception error)
        {
            return "error=" + error.GetType().Name;
        }
    }

    static byte[] ReadFrame(NamedPipeClientStream pipe, int timeoutMs)
    {
        byte[] header = new byte[40];
        if (!ReadExact(pipe, header, 40, timeoutMs))
        {
            return null;
        }

        uint cmdLen = BitConverter.ToUInt32(header, 20);
        uint msgLen = BitConverter.ToUInt32(header, 24);
        uint bodyLen = BitConverter.ToUInt32(header, 28);

        long total = 40L + cmdLen + msgLen + bodyLen;
        if (total > 32L * 1024 * 1024)
        {
            return header;
        }

        byte[] result = new byte[total];
        header.CopyTo(result, 0);

        long remaining = total - 40;
        if (remaining > 0)
        {
            byte[] rest = new byte[remaining];
            if (!ReadExact(pipe, rest, (int)remaining, timeoutMs))
            {
                return header;
            }
            rest.CopyTo(result, 40);
        }

        return result;
    }

    static bool ReadExact(NamedPipeClientStream pipe, byte[] buffer, int count, int timeoutMs)
    {
        int offset = 0;
        Stopwatch watch = Stopwatch.StartNew();

        while (offset < count)
        {
            if (watch.ElapsedMilliseconds > timeoutMs)
            {
                return false;
            }

            int read;
            try
            {
                read = pipe.Read(buffer, offset, count - offset);
            }
            catch
            {
                return false;
            }

            if (read <= 0)
            {
                return false;
            }

            offset += read;
        }

        return true;
    }

    static int Inject(int pid, string dllPath)
    {
        const uint PROCESS_ALL = 0x1F0FFF;
        const uint MEM_COMMIT_RESERVE = 0x3000;
        const uint PAGE_READWRITE = 0x04;
        const uint MEM_RELEASE = 0x8000;

        IntPtr process = OpenProcess(PROCESS_ALL, false, pid);
        if (process == IntPtr.Zero)
        {
            Console.WriteLine("OPEN_PROCESS_FAIL " + Marshal.GetLastWin32Error());
            return 1;
        }

        byte[] pathBytes = Encoding.ASCII.GetBytes(dllPath + "\0");
        IntPtr remote = VirtualAllocEx(process, IntPtr.Zero, (UIntPtr)pathBytes.Length, MEM_COMMIT_RESERVE, PAGE_READWRITE);
        if (remote == IntPtr.Zero)
        {
            Console.WriteLine("ALLOC_FAIL " + Marshal.GetLastWin32Error());
            CloseHandle(process);
            return 2;
        }

        UIntPtr written;
        if (!WriteProcessMemory(process, remote, pathBytes, (UIntPtr)pathBytes.Length, out written))
        {
            Console.WriteLine("WRITE_FAIL " + Marshal.GetLastWin32Error());
            CloseHandle(process);
            return 3;
        }

        IntPtr kernel32 = GetModuleHandleA("kernel32.dll");
        IntPtr loadLibrary = GetProcAddress(kernel32, "LoadLibraryA");

        uint threadId;
        IntPtr thread = CreateRemoteThread(process, IntPtr.Zero, UIntPtr.Zero, loadLibrary, remote, 0, out threadId);
        if (thread == IntPtr.Zero)
        {
            Console.WriteLine("THREAD_FAIL " + Marshal.GetLastWin32Error());
            CloseHandle(process);
            return 4;
        }

        WaitForSingleObject(thread, 20000);

        uint exitCode;
        GetExitCodeThread(thread, out exitCode);

        CloseHandle(thread);
        VirtualFreeEx(process, remote, UIntPtr.Zero, MEM_RELEASE);
        CloseHandle(process);

        if (exitCode == 0)
        {
            Console.WriteLine("INJECT_FAIL_HMODULE_NULL");
            return 5;
        }

        Console.WriteLine("INJECT_OK hmodule=0x" + exitCode.ToString("X"));
        injectedHmodule = (ulong)exitCode;
        return 0;
    }

    static ulong injectedHmodule = 0;

    static uint FindRemoteExportRva(int pid, ulong moduleBase, string name)
    {
        IntPtr process = OpenProcess(0x0410 /* VM_READ | QUERY_INFORMATION */, false, pid);
        if (process == IntPtr.Zero)
        {
            return 0;
        }
        uint result = 0;
        try
        {
            byte[] dos = new byte[64];
            if (!ReadProcessMemory(process, (IntPtr)(long)moduleBase, dos, 64, IntPtr.Zero))
            {
                return 0;
            }
            if (BitConverter.ToUInt16(dos, 0) != 0x5A4D)
            {
                return 0;
            }
            uint lfanew = BitConverter.ToUInt32(dos, 0x3C);
            byte[] nt = new byte[0x120];
            if (!ReadProcessMemory(process, (IntPtr)(long)(moduleBase + lfanew), nt, nt.Length, IntPtr.Zero))
            {
                return 0;
            }
            if (BitConverter.ToUInt32(nt, 0) != 0x00004550)
            {
                return 0;
            }
            uint exportRva = BitConverter.ToUInt32(nt, 0x88);
            uint exportSize = BitConverter.ToUInt32(nt, 0x8C);
            if (exportRva == 0 || exportSize == 0)
            {
                return 0;
            }
            byte[] dir = new byte[40];
            if (!ReadProcessMemory(process, (IntPtr)(long)(moduleBase + exportRva), dir, dir.Length, IntPtr.Zero))
            {
                return 0;
            }
            uint numberOfNames = BitConverter.ToUInt32(dir, 24);
            uint addressOfFunctions = BitConverter.ToUInt32(dir, 28);
            uint addressOfNames = BitConverter.ToUInt32(dir, 32);
            uint addressOfOrdinals = BitConverter.ToUInt32(dir, 36);
            for (uint i = 0; i < numberOfNames; i++)
            {
                byte[] nameRvaBytes = new byte[4];
                if (!ReadProcessMemory(process, (IntPtr)(long)(moduleBase + addressOfNames + i * 4), nameRvaBytes, 4, IntPtr.Zero))
                {
                    return 0;
                }
                uint nameRva = BitConverter.ToUInt32(nameRvaBytes, 0);
                byte[] nameBuffer = new byte[64];
                if (!ReadProcessMemory(process, (IntPtr)(long)(moduleBase + nameRva), nameBuffer, nameBuffer.Length, IntPtr.Zero))
                {
                    continue;
                }
                int length = 0;
                while (length < nameBuffer.Length && nameBuffer[length] != 0)
                {
                    length++;
                }
                string candidate = Encoding.ASCII.GetString(nameBuffer, 0, length);
                if (candidate != name)
                {
                    continue;
                }
                byte[] ordinalBytes = new byte[2];
                if (!ReadProcessMemory(process, (IntPtr)(long)(moduleBase + addressOfOrdinals + i * 2), ordinalBytes, 2, IntPtr.Zero))
                {
                    return 0;
                }
                ushort ordinal = BitConverter.ToUInt16(ordinalBytes, 0);
                byte[] functionRvaBytes = new byte[4];
                if (!ReadProcessMemory(process, (IntPtr)(long)(moduleBase + (ulong)addressOfFunctions + (ulong)(ordinal * 4)), functionRvaBytes, 4, IntPtr.Zero))
                {
                    return 0;
                }
                result = BitConverter.ToUInt32(functionRvaBytes, 0);
                break;
            }
        }
        finally
        {
            CloseHandle(process);
        }
        return result;
    }

    static uint FindFileExportRva(string dllPath, string name)
    {
        byte[] data = System.IO.File.ReadAllBytes(dllPath);
        ushort mz = BitConverter.ToUInt16(data, 0);
        if (mz != 0x5A4D)
        {
            return 0;
        }
        uint lfanew = BitConverter.ToUInt32(data, 0x3C);
        if (BitConverter.ToUInt32(data, (int)lfanew) != 0x00004550)
        {
            return 0;
        }
        int opt = (int)lfanew + 24;
        int numSections = BitConverter.ToUInt16(data, (int)lfanew + 6);
        uint optSize = BitConverter.ToUInt16(data, (int)lfanew + 20);
        int dirBase = opt + 112;
        uint exportRva = BitConverter.ToUInt32(data, dirBase);
        if (exportRva == 0)
        {
            return 0;
        }
        int secBase = opt + (int)optSize;
        Func<uint, int> r2o = delegate (uint rva)
        {
            for (int i = 0; i < numSections; i++)
            {
                int b = secBase + i * 40;
                uint vs = BitConverter.ToUInt32(data, b + 8);
                uint va = BitConverter.ToUInt32(data, b + 12);
                uint rs = BitConverter.ToUInt32(data, b + 16);
                uint rp = BitConverter.ToUInt32(data, b + 20);
                if (rva >= va && rva < va + vs && rva - va < rs)
                {
                    return (int)(rp + (rva - va));
                }
            }
            return -1;
        };
        int expOff = r2o(exportRva);
        if (expOff < 0)
        {
            return 0;
        }
        uint numNames = BitConverter.ToUInt32(data, expOff + 24);
        uint aof = BitConverter.ToUInt32(data, expOff + 28);
        uint aon = BitConverter.ToUInt32(data, expOff + 32);
        uint aoo = BitConverter.ToUInt32(data, expOff + 36);
        for (uint i = 0; i < numNames; i++)
        {
            int nOff = r2o(aon + i * 4);
            if (nOff < 0)
            {
                continue;
            }
            uint nameRva = BitConverter.ToUInt32(data, nOff);
            int sOff = r2o(nameRva);
            if (sOff < 0)
            {
                continue;
            }
            int end = sOff;
            while (end < data.Length && data[end] != 0)
            {
                end++;
            }
            string candidate = Encoding.ASCII.GetString(data, sOff, end - sOff);
            if (candidate != name)
            {
                continue;
            }
            int oOff = r2o(aoo + i * 2);
            if (oOff < 0)
            {
                return 0;
            }
            ushort ordinal = BitConverter.ToUInt16(data, oOff);
            int fOff = r2o(aof + (uint)ordinal * 4);
            if (fOff < 0)
            {
                return 0;
            }
            return BitConverter.ToUInt32(data, fOff);
        }
        return 0;
    }

    static ulong FindRemoteModuleBase(int pid, string moduleName)
    {
        IntPtr snapshot = CreateToolhelp32Snapshot(0x00000008 | 0x00000010, pid);
        if (snapshot == new IntPtr(-1))
        {
            return 0;
        }
        ulong result = 0;
        MODULEENTRY32W me = new MODULEENTRY32W();
        me.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32W));
        if (Module32FirstW(snapshot, ref me))
        {
            do
            {
                string mod = me.szModule ?? "";
                if (mod.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                {
                    result = (ulong)me.modBaseAddr.ToInt64();
                    break;
                }
            } while (Module32NextW(snapshot, ref me));
        }
        CloseHandle(snapshot);
        return result;
    }

    static void CallPrepareUnload(int pid, string dllPath)
    {
        string moduleName = System.IO.Path.GetFileName(dllPath);
        ulong moduleBase = FindRemoteModuleBase(pid, moduleName);
        if (moduleBase == 0)
        {
            Console.WriteLine("UNLOAD_TEST module not found: " + moduleName);
            return;
        }
        uint rva = FindFileExportRva(dllPath, "nexuslab_prepare_unload_v1");
        if (rva == 0)
        {
            Console.WriteLine("UNLOAD_TEST export not found");
            return;
        }
        ulong remote = moduleBase + rva;
        IntPtr process = OpenProcess(0x1F0FFF, false, pid);
        if (process == IntPtr.Zero)
        {
            Console.WriteLine("UNLOAD_TEST open process failed");
            return;
        }
        uint threadId;
        IntPtr thread = CreateRemoteThread(process, IntPtr.Zero, UIntPtr.Zero,
            (IntPtr)(long)remote, IntPtr.Zero, 0, out threadId);
        if (thread == IntPtr.Zero)
        {
            CloseHandle(process);
            Console.WriteLine("UNLOAD_TEST CreateRemoteThread failed");
            return;
        }
        uint wait = WaitForSingleObject(thread, 15000);
        uint code;
        GetExitCodeThread(thread, out code);
        CloseHandle(thread);
        CloseHandle(process);
        Console.WriteLine("UNLOAD_TEST rva=0x" + rva.ToString("X") + " wait=" + wait + " code=" + code);
    }
}