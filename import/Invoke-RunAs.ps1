# https://www.powershellgallery.com/packages/PSEasy.Utility/1.4.0/Content/UserPrivilege%5CInvoke-RunAs.ps1
# taken from RunAs module and added some additional verbose information and error handling to try to
# help troubleshoot strange errors such as "directory does not exist"

try {
    Add-Type -ErrorAction SilentlyContinue -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class RunAs
{
    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public uint dwProcessId, dwThreadId;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved, lpDesktop, lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessWithLogonW(string userName, string domain, string password, int logonFlags, string applicationName, string commandLine, int creationFlags, IntPtr environment, string currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);
    [DllImport("user32")]
    private static extern bool WaitForInputIdle(IntPtr lpEnvironment);
    [DllImport("userenv")]
    private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);
    [DllImport("userenv")]
    private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
    [DllImport("kernel32")]
    private static extern bool CloseHandle(IntPtr hObject);
    private static void SplitUsername(string username, out string user, out string domain)
    {
        var parts = username.Split('\\', '@');
        if (parts.Length == 1)
        {
            user = parts[0];
            domain = Environment.UserDomainName;
        }
        else if (username.Contains("@"))
        {
            user = parts[0];
            domain = parts[1];
        }
        else
        {
            user = parts[1];
            domain = parts[0];
        }
    }
    public static void Start(PSCredential credential, bool noProfile, bool env, bool netOnly, string applicationName, string commandLine, string currentDirectory)
    {
        var s = new STARTUPINFO();
        s.dwFlags = 1; // STARTF_USESHOWWINDOW
        s.wShowWindow = 1; // SW_SHOWNORMAL
        s.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        int logonFlags = 1; // LOGON_WITH_PROFILE
        if (noProfile) logonFlags = 0;
        if (netOnly) logonFlags = 2; // LOGON_NETCREDENTIALS_ONLY
        IntPtr lpEnvironment = IntPtr.Zero;
        int creationFlags = 0x04000000; // CREATE_DEFAULT_ERROR_MODE
        if (env)
        {
            CreateEnvironmentBlock(out lpEnvironment, IntPtr.Zero, false);
            creationFlags |= 0x00000400; // CREATE_UNICODE_ENVIRONMENT
        }
        try
        {
            string domain, username;
            SplitUsername(credential.UserName, out username, out domain);
            PROCESS_INFORMATION p;
            if (!CreateProcessWithLogonW(username, domain, credential.GetNetworkCredential().Password, logonFlags, applicationName, commandLine, creationFlags, lpEnvironment, currentDirectory, ref s, out p))
                throw new Win32Exception(Marshal.GetLastWin32Error());
 
            CloseHandle(p.hProcess);
            CloseHandle(p.hThread);
        }
        finally
        {
            if (env) DestroyEnvironmentBlock(lpEnvironment);
        }
    }
}
'@
}
catch {
    Write-Verbose "RunAs class already exists"
    # ignore if we already exist (TODO find a better solution to this)
}

<#
.Synopsis
A version of the Windows 'runas' command that accepts a PSCredential instead of prompting for a password.
.Description
Allows a user to run specific tools and programs with different permissions than the user's current logon provides.
.Parameter noprofile
Specifies that the user's profile should not be loaded. This causes the application to load more quickly, but can cause some applications to malfunction.
.Parameter env
To use current environment instead of user's.
.Parameter netonly
Use if the credentials specified are for remote access only.
.Parameter user
Username should be in form user@domain or domain\user.
.Parameter program
Command line for EXE. See below for examples.
.Example
...
runas -noprofile -user mymachine\administrator cmd
runas -env -user mydomain\admin mmc %windir%\system32\eventvwr.msc
runas -env -user user@domain.microsoft.com notepad "my file.txt"
#>
function Invoke-RunAs {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        <#Category#>'PSUseSingularNouns', <#CheckId#>'',
        Justification = 'RunAs is singular'
    )]
    [CmdletBinding()]
    param(
        [switch]$noProfile,
        [switch]$env,
        [switch]$netOnly,
        [Parameter(Mandatory = $true)][PSCredential]$user,
        [Parameter(Mandatory = $true)][string]$program,
        [Parameter(ValueFromRemainingArguments = $true)][string]$arguments
    )
    try {
        if (!(test-path $program)) {
            $cmd = (get-command $program -ea ignore)
            if ($cmd -and $cmd.path) { $program = $cmd.path }
        }
        $commandLine = " $([Environment]::ExpandEnvironmentVariables($arguments))"
        $currentDirectory = $pwd.Path
        $allParams = @{
            credential       = $user
            noProfile        = $noProfile
            env              = $env
            netOnly          = $netOnly
            applicationName  = $program
            commandLine      = $commandLine
            currentDirectory = $currentDirectory
        }
        $allParams | Format-Table | Out-String | Write-Verbose
        [RunAs]::Start($user, $noProfile, $env, $netOnly, $program, $commandLine, $currentDirectory)
    }
    catch {
        throw
    }
}

# Export-ModuleMember -function RunAs