### strings

The Linux `strings` builtin and the Windows `sysinternals` `strings` utility can
be used to extract the printable characters contained in a file, and notably
in non-text files.

By default, only the sequences that are at least 4 characters long are
retrieved.

```
strings <BINARY>
```

### objdump

The GNU `objdump` command line utility can be used to disassemble the assembler
contents of the executable sections of a binary:

```
objdump -d <BINARY>
```

### radare2

The `radare2` suite is an open source reverse engineering framework consisting
of multiples tools and features.

The framework supports multiples architectures (i386, x86-64, ARM, etc.),
file formats (PE, PE+, ELF, Mach-O, etc.) and operating systems (Windows,
GNU/Linux, OS X, etc.).

The `rabin2` utility can be used to retrieve information and protection
mechanisms of a binary:

```
rabin2 -I <BINARY>

radar2 <BINARY>
[0xXXX] > iL
```

The strings in the binary can be printed and searched into using `izz`:

```
[0xXXX] > iiz
[0xXXX] > iiz~<SEARCH_KEYWORD>
[0xXXX] > iiz~password
```

The visual mode can entered by using the `v` command and quitted using the `q`
command. In visual mode, the `p` command can be used to switch between display
mode.


### GDB

###### Binaries without debugging symbols

Debugging a binary compiled with out the debbugging symbols ("no debugging
symbols found") is possible as GDB can directly handle assembly code.

GDB uses By default the AT&T assembly syntax. The following command can be used
to switch to the Intel syntax:  

```
set disassembly-flavor intel
```

To setup a breakpoint, the binary entry point can be retrieved using the GDB
`info` command:

```
(gdb) info file
Entry point: 0xXXXXXX

b *0xXXXXXX
```

The `nexti` (shortcut `ni`) and the `stepi` (shortcut `si`) commands are the
assembly counter part of the soure code `next` and `step` commands.

The `examine` (shortcut `x`) command can be used to display the assembly code
after the breakpoint:

```
# N = number of assembly line to print
# $pc = GDB variable for the program counter register

x/<N>i $pc
x/5i $pc
```

### OllyDbg

`OllyDbg` is a GUI 32-bit assembler level analyzing debugger for Microsoft
Windows.

The `Search for -> All referenced strings` functionality allows to retrieve all
printable strings contained in the binary and their address location for
breakpoint setting.   

### dnSpy

`dnSpy` is a GUI debugger and assembly editor which can be used to debug 32
or 64 bits .NET applications and edit assemblies in C# or Visual Basic.

The GUI interface can be launched using the `dnSpy.exe` or `dnSpy-x86.exe`
programs.
