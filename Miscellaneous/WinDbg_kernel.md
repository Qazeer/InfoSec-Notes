### Sources

Based on:

  - Microsoft Windows Debugging Tools official documentation

    https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/

  - "Modern Debugging with WinDbg Preview" DEFCON 27 workshop by hugsy and
    0vercl0k

    https://github.com/hugsy/defcon_27_windbg_workshop

  - "WinDbg — the Fun Way: Part 1 / 2" by Yarden Shafir

    https://medium.com/@yardenshafir2/windbg-the-fun-way-part-1-2e4978791f9b
    https://medium.com/@yardenshafir2/windbg-the-fun-way-part-2-7a904cba5435

### CheatSheet

###### Symbols and types

| Command | Usage  | Examples | Description |
|---------|---------|---------|-------------|
| [lm (List Loaded Modules)](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/lm--list-loaded-modules-) | `lm` <br><br> `lm <PATTERN>` | `lm nt*` | Displays all or the specified loaded modules. |
| [x (Examine Symbols)](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/x--examine-symbols-) | `x <MODULE>!*` <br><br> `x <MODULE>!<PATTERN>` |  `x nt!*` <br><br> `x nt!*process*` | Displays the symbols in the specified module. |
| [ln (List Nearest Symbols)](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/ln--list-nearest-symbols-) | `ln <ADDRESS>` | `ln fffff80705d4c9d4` | Displays the symbol(s) at or near the specified address. |
| [dt (Display Type)](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/dt--display-type-) | `dt <STRUCT>` <br><br> `dt nt!*<PATTERN>*` | `dt nt!_EPROCESS` | Displays information about a local variable, global variable or data type. |
| [.printf](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-printf) | `.printf [<OPTIONS>] <FORMAT_STRING> <ARGUMENT \| ARGUMENT_LIST>` | `.printf "%y", <ADDRESS>` <br> displays the eventual symbol associated with the given address. | C printf-like function. |

###### Memory exploration

| Command | Usage  | Examples | Description |
|---------|---------|---------|-------------|
| [dds, dps, dqs (Display Words and Symbols)](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/dds--dps--dqs--display-words-and-symbols-) | `d*s <ADDRESS \| ADDRESS_RANGE>` | `dqs fffff80705d1a410` <br><br> `dqs fffff80705d1a410 fffff80705d1a418` | Displays the contents of memory in the given range. <br><br> The `dds` command displays `DWORD` (4 byte) values. <br><br> The `dqs` command displays `QWORD` (8 byte) values. <br><br> The `dps` command displays pointer-sized values (4 byte or 8 byte depending on the system architecture) values. |
| [ds, dS (Display String)](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/ds--ds--display-string-) | `ds <ADDRESS>` <br><br> `dS <ADDRESS>` | | Display a `STRING` / `ANSI_STRING` (`ds`) or `UNICODE_STRING` (`dS`) strings. |
| [u, ub, uu (Unassemble)](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/u--unassemble-) | `u <ADDRESS \| ADDRESS_RANGE>` | `u 0xfffff8015be478d0` <br><br> `u nt!NtOpenProcessToken` | Displays an assembly translation of the code at the specified memory address or range. |
| [uf (Unassemble Function)](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/uf--unassemble-function-) | `u <ADDRESS>` | `uf fffff80705685060` <br><br> `uf nt!NtOpenProcessTokenEx` | Displays an assembly translation of the function at the specified memory address. |
| [!address](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-address) | `!address <ADDRESS>` | `!address fffff80705d1a410` <br><br> `!address nt!NtOpenProcessTokenEx` | Displays information on the module to which the specified address belong (module name, path and base start / end ADDRESSs).  |
| *[dx advised]* <br> [!process](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-process) | `!process [/s <SESSION>] [/m <MODULE>] <0 \| PROCESS_ADDRESS \| PROCESS_PID> <INFORMATION_LEVEL_FLAG>]` | `!process 0 0` <br> display all the process of the system, with a minimum level of information. | Displays information about all or the specified processes, including the `EPROCESS` block. |
| *[dx advised]* <br> [!thread](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-thread) | `!thread [-p] [-t] <ADDRESS>` | `!thread 0xffffcb088f0d6840` <br> display all the process of the system, with a minimum level of information. | Displays summary information about a thread, including the `ETHREAD` block. |
| [!acl](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-acl) | `!acl <HEXA_ADDRESS>` |  | Displays the contents of an `Access Control List (ACL)`. |
| `poi(<ADDRESS>)` | | | Dereference pointer |

###### Display Debugger Object Model Expression (dx)

```c++
dx <CPP_EXPRESSION>

// Displays information about the specified variable (using the variable address directly or the variable eventual symbol).
dx (<TYPE> *) <ADDRESS>
dx (<TYPE> *) &<VARIABLE>
// If the variable is a pointer to an object.
dx (<TYPE> **) &<VARIABLE>

// Examples:
dx -r1 (ntkrnlmp!_EPROCESS *) 0xffffa10d10c37080
dx (nt!_EPROCESS *) &nt!PsIdleProcess
dx *(nt!_OBJECT_TYPE **) &nt!AlpcPortObjectType

// Displays the first debugging session processes as a grid view.
dx -g Debugger.Sessions.First().Processes

// Displays the first debugging session processes as a grid view.
dx -g Debugger.Sessions.First().Processes

// Displays information about the process PID in the first debugging session.
dx Debugger.Sessions.First().Processes[<DECIMAL_PID>]

// Displays the threads of the first or specified process in the first debugging session processes as a grid view.
dx -g Debugger.Sessions.First().Processes.First().Threads
dx -g Debugger.Sessions.First().Processes[<DECIMAL_PID>].Threads

// Displays the loaded module of the first or specified process in the first debugging session processes as a grid view.
dx -g Debugger.Sessions.First().Processes.First().Modules
dx -g Debugger.Sessions.First().Processes[<DECIMAL_PID>].Modules

// Retrieve the first or specified thread of the specified process in the first debugging session.
dx -r1 Debugger.Sessions.First().Processes[<DECIMAL_PID>].Threads.First()
dx -r1 Debugger.Sessions.First().Processes[<DECIMAL_PID>].Threads[<DECIMAL_THREAD_ID>]

// Stores the specified process as a variable, allowing later reference to the process properties.
dx @$process = Debugger.Sessions.First().Processes[<DECIMAL_PID>]
dx @$process->Name
dx @$process->Threads
// Get process Ldr.
dx -r2 (_PEB_LDR_DATA *) @$process.Environment.EnvironmentBlock.Ldr

// Stores the specified process handles in a variable and display all or selected information about each handle.
dx @$processHandles = Debugger.Sessions.First().Processes[<DECIMAL_PID>].Io.Handles
// Display all available information.
dx -g @$processHandles
// Displays selected information.
dx -g @$processHandles->Select(o => new { Handle = o->Handle, Type = o->Type, ObjectName = o->ObjectName})
// Filters handles of type "Directory" and displays selected information.
dx -g @$processHandles->Where(o => (o.Type == "Directory"))->Select(o => new { Handle = o->Handle, Type = o->Type, ObjectName = o->ObjectName})

// Get process Ldr first entry (in memory order).
dx -r1 @$process.Environment.EnvironmentBlock.Ldr->InMemoryOrderModuleList.Flink
```

###### Execution control flow

| Command | Usage  | Examples | Description |
|---------|---------|---------|-------------|
| [bp, bu, bm (Set Breakpoint)](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bp--bu--bm--set-breakpoint-) |
| [bl (Breakpoint List)](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bl--breakpoint-list-) |
| [g (Go)](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/g--go-) |
