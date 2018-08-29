/*
 * Copyright 2002-2013 Jose Fonseca
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <cstdio>
#include <cassert>
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <ntstatus.h>
#include <tlhelp32.h>

#ifndef STATUS_CPP_EH_EXCEPTION
#define STATUS_CPP_EH_EXCEPTION 0xE06D7363
#endif
#ifndef STATUS_CLR_EXCEPTION
#define STATUS_CLR_EXCEPTION 0xE0434f4D
#endif

#define MAX_SYM_NAME_SIZE 512

#define REPORT_FILE 1


static HANDLE g_hReportFile = 0;
static char g_szLogFileName[MAX_PATH] = "";
static BOOL g_bOwnReportFile = false;


static inline const char *
getSeparator(const char *szFilename) {
    const char *p, *q;
    p = NULL;
    q = szFilename;
    char c;
    do  {
        c = *q++;
        if (c == '\\' || c == '/' || c == ':') {
            p = q;
        }
    } while (c);
    return p;
}


static inline const char *
getBaseName(const char *szFilename) {
    const char *pSeparator = getSeparator(szFilename);
    if (!pSeparator) {
        return szFilename;
    }
    return pSeparator;
}


static BOOL
getModuleVersionInfo(LPCSTR szModule, DWORD *dwVInfo)
{
    DWORD dummy, size;
    BOOL success = FALSE;

  #if 0
    size = GetFileVersionInfoSizeA(szModule, &dummy);
    if (size > 0) {
        LPVOID pVer = malloc(size);
        ZeroMemory(pVer, size);
        if (GetFileVersionInfoA(szModule, 0, size, pVer)) {
            VS_FIXEDFILEINFO *ffi;
            if (VerQueryValueA(pVer, "\\", (LPVOID *) &ffi,  (UINT *) &dummy)) {
                dwVInfo[0] = ffi->dwFileVersionMS >> 16;
                dwVInfo[1] = ffi->dwFileVersionMS & 0xFFFF;
                dwVInfo[2] = ffi->dwFileVersionLS >> 16;
                dwVInfo[3] = ffi->dwFileVersionLS & 0xFFFF;
                success = TRUE;
            }
        }
        free(pVer);
    }
#endif
    return success;
}


static void
dump(const char *szText)
{
    fprintf(stderr, "%s", szText);

    if (REPORT_FILE) {
        DWORD cbWritten;
        while (*szText != '\0') {
            const char *p = szText;
            while (*p != '\0' && *p != '\n') {
                ++p;
            }
            WriteFile(g_hReportFile, szText, p - szText, &cbWritten, 0);
            if (*p == '\n') {
                WriteFile(g_hReportFile, "\r\n", 2, &cbWritten, 0);
                ++p;
            }
            szText = p;
        }
    }
}


#ifdef __GNUC__
    __attribute__ ((format (printf, 1, 2)))
#endif
int lprintf(const char * format, ...)
{
    char szBuffer[1024];
    int retValue;
    va_list ap;

    va_start(ap, format);
    retValue = _vsnprintf(szBuffer, sizeof szBuffer, format, ap);
    va_end(ap);

    dump(szBuffer);

    return retValue;
}

/*
 * Get the message string for the exception code.
 *
 * Per https://support.microsoft.com/en-us/kb/259693 one could supposedly get
 * these from ntdll.dll via FormatMessage but the matter of fact is that the
 * FormatMessage is hopeless for that, as described in:
 * - http://www.microsoft.com/msj/0497/hood/hood0497.aspx
 * - http://stackoverflow.com/questions/321898/how-to-get-the-name-description-of-an-exception
 * - http://www.tech-archive.net/Archive/Development/microsoft.public.win32.programmer.kernel/2006-05/msg00683.html
 *
 * See also:
 * - https://msdn.microsoft.com/en-us/library/windows/hardware/ff558784.aspx
 */
static LPCSTR
getExceptionString(DWORD ExceptionCode)
{
    switch (ExceptionCode) {

    case EXCEPTION_ACCESS_VIOLATION: // 0xC0000005
        return "Access Violation";
    case EXCEPTION_IN_PAGE_ERROR: // 0xC0000006
        return "In Page Error";
    case EXCEPTION_INVALID_HANDLE: // 0xC0000008
        return "Invalid Handle";
    case EXCEPTION_ILLEGAL_INSTRUCTION: // 0xC000001D
        return "Illegal Instruction";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: // 0xC0000025
        return "Cannot Continue";
    case EXCEPTION_INVALID_DISPOSITION: // 0xC0000026
        return "Invalid Disposition";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: // 0xC000008C
        return "Array bounds exceeded";
    case EXCEPTION_FLT_DENORMAL_OPERAND: // 0xC000008D
        return "Floating-point denormal operand";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO: // 0xC000008E
        return "Floating-point division by zero";
    case EXCEPTION_FLT_INEXACT_RESULT: // 0xC000008F
        return "Floating-point inexact result";
    case EXCEPTION_FLT_INVALID_OPERATION: // 0xC0000090
        return "Floating-point invalid operation";
    case EXCEPTION_FLT_OVERFLOW: // 0xC0000091
        return "Floating-point overflow";
    case EXCEPTION_FLT_STACK_CHECK: // 0xC0000092
        return "Floating-point stack check";
    case EXCEPTION_FLT_UNDERFLOW: // 0xC0000093
        return "Floating-point underflow";
    case EXCEPTION_INT_DIVIDE_BY_ZERO: // 0xC0000094
        return "Integer division by zero";
    case EXCEPTION_INT_OVERFLOW:  // 0xC0000095
        return "Integer overflow";
    case EXCEPTION_PRIV_INSTRUCTION: // 0xC0000096
        return "Privileged instruction";
    case EXCEPTION_STACK_OVERFLOW: // 0xC00000FD
        return "Stack Overflow";
    case EXCEPTION_POSSIBLE_DEADLOCK: // 0xC0000194
        return "Possible deadlock condition";
    case STATUS_ASSERTION_FAILURE: // 0xC0000420
        return "Assertion failure";

    case STATUS_CLR_EXCEPTION: // 0xE0434f4D
        return "CLR exception";
    case STATUS_CPP_EH_EXCEPTION: // 0xE06D7363
        return "C++ exception handling exception";

    case EXCEPTION_GUARD_PAGE: // 0x80000001
        return "Guard Page Exception";
    case EXCEPTION_DATATYPE_MISALIGNMENT: // 0x80000002
        return "Alignment Fault";
    case EXCEPTION_BREAKPOINT: // 0x80000003
        return "Breakpoint";
    case EXCEPTION_SINGLE_STEP: // 0x80000004
        return "Single Step";

    case STATUS_WX86_BREAKPOINT: // 0x4000001F
        return "Breakpoint";
    case DBG_TERMINATE_THREAD: // 0x40010003
        return "Terminate Thread";
    case DBG_TERMINATE_PROCESS: // 0x40010004
        return "Terminate Process";
    case DBG_CONTROL_C: // 0x40010005
        return "Control+C";
    case DBG_CONTROL_BREAK: // 0x40010008
        return "Control+Break";
    case 0x406D1388:
        return "Thread Name Exception";

    case RPC_S_UNKNOWN_IF:
        return "Unknown Interface";
    case RPC_S_SERVER_UNAVAILABLE:
        return "Server Unavailable";

    default:
        return NULL;
    }
}


void
dumpException(HANDLE hProcess,
              PEXCEPTION_RECORD pExceptionRecord)
{
    NTSTATUS ExceptionCode = pExceptionRecord->ExceptionCode;

    char szModule[MAX_PATH];
    const char *process_name = 0;
    HMODULE hModule;

    if (GetModuleFileNameA(GetModuleHandle(0), szModule, MAX_PATH)) {
        process_name = getBaseName(szModule);
    } else {
        process_name = "Application";
    }

    // First print information about the type of fault
    lprintf("%s caused", process_name);

    LPCSTR lpcszException = getExceptionString(ExceptionCode);
    if (lpcszException) {
        LPCSTR lpszArticle;
        switch (lpcszException[0]) {
        case 'A':
        case 'E':
        case 'I':
        case 'O':
        case 'U':
            lpszArticle = "an";
            break;
        default:
            lpszArticle = "a";
            break;
        }

        lprintf(" %s %s", lpszArticle, lpcszException);
    } else {
        lprintf(" an Unknown [0x%lX] Exception", ExceptionCode);
    }

    // Now print information about where the fault occurred
    lprintf(" at location %p", pExceptionRecord->ExceptionAddress);
//     cerr<<endl<<"ExceptionAddress: "<<pExceptionRecord->ExceptionAddress<<endl;

    hModule =
        (HMODULE)(INT_PTR)
          SymGetModuleBase64(hProcess, (DWORD64)(INT_PTR)pExceptionRecord->ExceptionAddress);


//     cout<<" module handle: "<<hModule<<endl;

    if(hModule && GetModuleFileNameA(hModule, szModule, sizeof szModule))
    {
        lprintf(" in module %s", getBaseName(szModule));
    }

    // If the exception was an access violation, print out some additional information, to the error log and the debugger.
    // https://msdn.microsoft.com/en-us/library/windows/desktop/aa363082%28v=vs.85%29.aspx
    if ((ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
         ExceptionCode == EXCEPTION_IN_PAGE_ERROR) &&
        pExceptionRecord->NumberParameters >= 2) {
        LPCSTR lpszVerb;
        switch (pExceptionRecord->ExceptionInformation[0]) {
        case 0:
            lpszVerb = "Reading from";
            break;
        case 1:
            lpszVerb = "Writing to";
            break;
        case 8:
            lpszVerb = "DEP violation at";
            break;
        default:
            lpszVerb = "Accessing";
            break;
        }

        lprintf(" %s location %p", lpszVerb, (PVOID)pExceptionRecord->ExceptionInformation[1]);
    }

    lprintf(".\n\n");
}


EXTERN_C BOOL
InitializeSym(HANDLE hProcess, BOOL fInvadeProcess)
{
    // Provide default symbol search path
    // https://msdn.microsoft.com/en-us/library/windows/desktop/ms680689.aspx
    // http://msdn.microsoft.com/en-gb/library/windows/hardware/ff558829.aspx
    char szSymSearchPathBuf[MAX_PATH * 2];
    const char *szSymSearchPath = NULL;
    if (getenv("_NT_SYMBOL_PATH") == NULL &&
        getenv("_NT_ALT_SYMBOL_PATH") == NULL) {
//         char szLocalAppData[MAX_PATH];
//         HRESULT hr = SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, szLocalAppData);
//         assert(SUCCEEDED(hr));
//         if (SUCCEEDED(hr)) {
//             _snprintf(szSymSearchPathBuf,
//                       sizeof szSymSearchPathBuf,
//                       "srv*%s\\drmingw*http://msdl.microsoft.com/download/symbols",
//                       szLocalAppData);
//             szSymSearchPath = szSymSearchPathBuf;
//         } else {
            // No cache
            szSymSearchPath = "srv*http://msdl.microsoft.com/download/symbols";
//         }
    }

    return SymInitialize(hProcess, szSymSearchPath, fInvadeProcess);
//     return SymInitialize(hProcess, 0, fInvadeProcess);
}


BOOL
GetSymFromAddr(HANDLE hProcess, DWORD64 dwAddress, LPSTR lpSymName, DWORD nSize)
{
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)malloc(sizeof(SYMBOL_INFO) + nSize * sizeof(char));

    DWORD64 dwDisplacement = 0;  // Displacement of the input address, relative to the start of the symbol
    BOOL bRet;

    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = nSize;

    DWORD dwOptions = SymGetOptions();

    bRet = SymFromAddr(hProcess, dwAddress, &dwDisplacement, pSymbol);

    if (bRet) {
        // Demangle if not done already
        if ((dwOptions & SYMOPT_UNDNAME) ||
            UnDecorateSymbolName(pSymbol->Name, lpSymName, nSize, UNDNAME_NAME_ONLY) == 0) {
            strncpy(lpSymName, pSymbol->Name, nSize);
        }
    }

    free(pSymbol);

    return bRet;
}


BOOL
GetLineFromAddr(HANDLE hProcess, DWORD64 dwAddress,  LPSTR lpFileName, DWORD nSize, LPDWORD lpLineNumber)
{
    IMAGEHLP_LINE64 Line;
    DWORD dwDisplacement = 0;  // Displacement of the input address, relative to the start of the symbol

    // Do the source and line lookup.
    memset(&Line, 0, sizeof Line);
    Line.SizeOfStruct = sizeof Line;

    if(!SymGetLineFromAddr64(hProcess, dwAddress, &dwDisplacement, &Line))
        return FALSE;

    assert(lpFileName && lpLineNumber);

    strncpy(lpFileName, Line.FileName, nSize);
    *lpLineNumber = Line.LineNumber;

    return TRUE;
}


static void
dumpContext(PCONTEXT pContext)
{
    // Show the registers
    lprintf("Registers:\n");
    if (pContext->ContextFlags & CONTEXT_INTEGER) {
        lprintf(
            "eax=%08lx ebx=%08lx ecx=%08lx edx=%08lx esi=%08lx edi=%08lx\n",
            pContext->Eax,
            pContext->Ebx,
            pContext->Ecx,
            pContext->Edx,
            pContext->Esi,
            pContext->Edi
        );
    }
    if (pContext->ContextFlags & CONTEXT_CONTROL) {
        lprintf(
            "eip=%08lx esp=%08lx ebp=%08lx iopl=%1lx %s %s %s %s %s %s %s %s %s %s\n",
            pContext->Eip,
            pContext->Esp,
            pContext->Ebp,
            (pContext->EFlags >> 12) & 3,    //  IOPL level value
            pContext->EFlags & 0x00100000 ? "vip" : "   ",    //  VIP (virtual interrupt pending)
            pContext->EFlags & 0x00080000 ? "vif" : "   ",    //  VIF (virtual interrupt flag)
            pContext->EFlags & 0x00000800 ? "ov" : "nv",    //  VIF (virtual interrupt flag)
            pContext->EFlags & 0x00000400 ? "dn" : "up",    //  OF (overflow flag)
            pContext->EFlags & 0x00000200 ? "ei" : "di",    //  IF (interrupt enable flag)
            pContext->EFlags & 0x00000080 ? "ng" : "pl",    //  SF (sign flag)
            pContext->EFlags & 0x00000040 ? "zr" : "nz",    //  ZF (zero flag)
            pContext->EFlags & 0x00000010 ? "ac" : "na",    //  AF (aux carry flag)
            pContext->EFlags & 0x00000004 ? "po" : "pe",    //  PF (parity flag)
            pContext->EFlags & 0x00000001 ? "cy" : "nc"    //  CF (carry flag)
        );
    }
    if (pContext->ContextFlags & CONTEXT_SEGMENTS) {
        lprintf(
            "cs=%04lx  ss=%04lx  ds=%04lx  es=%04lx  fs=%04lx  gs=%04lx",
            pContext->SegCs,
            pContext->SegSs,
            pContext->SegDs,
            pContext->SegEs,
            pContext->SegFs,
            pContext->SegGs
        );
        if (pContext->ContextFlags & CONTEXT_CONTROL) {
            lprintf(
                "             efl=%08lx",
                pContext->EFlags
            );
        }
    }
    else {
        if (pContext->ContextFlags & CONTEXT_CONTROL) {
            lprintf(
                "                                                                       efl=%08lx",
                pContext->EFlags
            );
        }
    }

    lprintf("\n\n");
}


static BOOL
dumpSourceCode(LPCSTR lpFileName, DWORD dwLineNumber)
{
    FILE *fp;
    unsigned i;
    char szFileName[MAX_PATH] = "";
    DWORD dwContext = 2;

    if(lpFileName[0] == '/' && lpFileName[1] == '/')
    {
        szFileName[0] = lpFileName[2];
        szFileName[1] = ':';
        strcpy(szFileName + 2, lpFileName + 3);
    }
    else
        strcpy(szFileName, lpFileName);

    if((fp = fopen(szFileName, "r")) == NULL)
        return FALSE;

    i = 0;
    while(!feof(fp) && ++i <= dwLineNumber + dwContext)
    {
        int c;

        if((int)i >= (int) dwLineNumber - (int)dwContext)
        {
            lprintf(i == dwLineNumber ? ">%5i: " : "%6i: ", i);
            while(!feof(fp) && (c = fgetc(fp)) != '\n')
                if(isprint(c))
                    lprintf("%c", c);
            lprintf("\n");
        }
        else
            while(!feof(fp) && (c = fgetc(fp)) != '\n')
                ;
    }

    fclose(fp);
    return TRUE;
}


void
dumpModules(HANDLE hProcess)
{

    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        return;
    }

    MODULEENTRY32 me32;
    me32.dwSize = sizeof me32;
    if (Module32First(hModuleSnap, &me32)) {
        do  {
            const char *szBaseName = getBaseName(me32.szExePath);
            DWORD dwVInfo[4];
            if (getModuleVersionInfo(me32.szExePath, dwVInfo)) {
                lprintf(
                    "%-12s\t%lu.%lu.%lu.%lu\n",
                    szBaseName,
                    dwVInfo[0],
                    dwVInfo[1],
                    dwVInfo[2],
                    dwVInfo[3]
                );
            } else {
                lprintf( "%s (%s)\n", szBaseName, me32.szExePath);
            }
        } while (Module32Next(hModuleSnap, &me32));
        lprintf("\n");
    }

    CloseHandle(hModuleSnap);
}


void
dumpStack(HANDLE hProcess, HANDLE hThread,
          const CONTEXT *pTargetContext)
{
    DWORD MachineType;

    CONTEXT Context;
    ZeroMemory(&Context, sizeof Context);
    Context.ContextFlags = CONTEXT_FULL;
    PCONTEXT pContext;

    STACKFRAME64 StackFrame;
    ZeroMemory(&StackFrame, sizeof StackFrame);

    if (pTargetContext) {
        assert(hProcess == GetCurrentProcess());
        assert((pTargetContext->ContextFlags & CONTEXT_FULL) == CONTEXT_FULL);
    }

    {
        if (pTargetContext) {
            Context = *pTargetContext;
        } else {
            if (!GetThreadContext(hThread, &Context)) {
                // XXX: This happens with WINE after EXIT_PROCESS_DEBUG_EVENT
                return;
            }
        }
        pContext = &Context;

        MachineType = IMAGE_FILE_MACHINE_I386;
        dumpContext(pContext);
        StackFrame.AddrPC.Offset = pContext->Eip;
        StackFrame.AddrPC.Mode = AddrModeFlat;
        StackFrame.AddrStack.Offset = pContext->Esp;
        StackFrame.AddrStack.Mode = AddrModeFlat;
        StackFrame.AddrFrame.Offset = pContext->Ebp;
        StackFrame.AddrFrame.Mode = AddrModeFlat;
    }

    if (MachineType == IMAGE_FILE_MACHINE_I386) {
        lprintf( "AddrPC   Params\n" );
    } else {
        lprintf( "AddrPC           Params\n" );
    }

//FIXME
    BOOL bInsideWine = false;
//     isInsideWine();

    DWORD64 PrevFrameStackOffset = StackFrame.AddrStack.Offset - 1;
    int nudge = 0;

    while (TRUE) {
        char szSymName[MAX_SYM_NAME_SIZE] = "";
        char szFileName[MAX_PATH] = "";
        DWORD dwLineNumber = 0;

        if (!StackWalk64(
                MachineType,
                hProcess,
                hThread,
                &StackFrame,
                pContext,
                NULL, // ReadMemoryRoutine
                SymFunctionTableAccess64,
                SymGetModuleBase64,
                NULL // TranslateAddress
            )
        )
            break;

        if (MachineType == IMAGE_FILE_MACHINE_I386) {
            lprintf(
                "%08lX %08lX %08lX %08lX",
                (DWORD)StackFrame.AddrPC.Offset,
                (DWORD)StackFrame.Params[0],
                (DWORD)StackFrame.Params[1],
                (DWORD)StackFrame.Params[2]
            );
        } else {
            lprintf(
                "%016I64X %016I64X %016I64X %016I64X",
                StackFrame.AddrPC.Offset,
                StackFrame.Params[0],
                StackFrame.Params[1],
                StackFrame.Params[2]
            );
        }

        BOOL bSymbol = TRUE;
        BOOL bLine = FALSE;

        DWORD64 AddrPC = StackFrame.AddrPC.Offset;
        HMODULE hModule = (HMODULE)(INT_PTR)SymGetModuleBase64(hProcess, AddrPC);
        char szModule[MAX_PATH];
        if (hModule &&
            GetModuleFileNameA(hModule, szModule, MAX_PATH)) {

            lprintf( "  %s", getBaseName(szModule));

            bSymbol = GetSymFromAddr(hProcess, AddrPC + nudge, szSymName, MAX_SYM_NAME_SIZE);
            if (bSymbol) {
                lprintf( "!%s", szSymName);

                bLine = GetLineFromAddr(hProcess, AddrPC + nudge, szFileName, MAX_PATH, &dwLineNumber);
                if (bLine) {
                    lprintf( "  [%s @ %ld]", szFileName, dwLineNumber);
                }
            } else {
                lprintf( "!0x%I64x", AddrPC - (DWORD)(INT_PTR)hModule);
            }
        }

        lprintf("\n");

        if (bLine) {
            dumpSourceCode(szFileName, dwLineNumber);
        }

        // Basic sanity check to make sure  the frame is OK.  Bail if not.
        if (StackFrame.AddrStack.Offset <= PrevFrameStackOffset ||
            StackFrame.AddrPC.Offset == 0xBAADF00D) {
            break;
        }
        PrevFrameStackOffset = StackFrame.AddrStack.Offset;

        // Wine's StackWalk64 implementation on certain yield never ending
        // stack backtraces unless one bails out when AddrFrame is zero.
        if (bInsideWine && StackFrame.AddrFrame.Offset == 0) {
            break;
        }

        /*
         * When we walk into the callers, StackFrame.AddrPC.Offset will not
         * contain the calling function's address, but rather the return
         * address.  This could be the next statement, or sometimes (for
         * no-return functions) a completely different function, so nudge the
         * address by one byte to ensure we get the information about the
         * calling statment itself.
         */
        nudge = -1;
    }

    lprintf("\n");
}


void
GenerateExceptionReport(PEXCEPTION_POINTERS pExceptionInfo)
{
    PEXCEPTION_RECORD pExceptionRecord = pExceptionInfo->ExceptionRecord;

    // Start out with a banner
    lprintf("-------------------\n\n");

    SYSTEMTIME SystemTime;
    GetLocalTime(&SystemTime);
    char szDateStr[128];
    LCID Locale = MAKELCID(MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), SORT_DEFAULT);
    GetDateFormatA(Locale, 0, &SystemTime, "dddd',' MMMM d',' yyyy", szDateStr, _countof(szDateStr));
    char szTimeStr[128];
    GetTimeFormatA(Locale, 0, &SystemTime, "HH':'mm':'ss", szTimeStr, _countof(szTimeStr));
    lprintf("Error occurred on %s at %s.\n\n", szDateStr, szTimeStr);

    HANDLE hProcess = GetCurrentProcess();

//FIXME
//     SetSymOptions(FALSE);

    if (InitializeSym(hProcess, TRUE)) {

        dumpException(hProcess, pExceptionRecord);

        PCONTEXT pContext = pExceptionInfo->ContextRecord;

        PVOID ip = (PVOID)pContext->Eip;
        if (pExceptionRecord->ExceptionAddress != ip) {
            lprintf("warning: inconsistent exception context record\n");
        }

        dumpStack(hProcess, GetCurrentThread(), pContext);

        if (!SymCleanup(hProcess)) {
            assert(0);
        }
    }

    dumpModules(hProcess);

    // TODO: Use GetFileVersionInfo on kernel32.dll as recommended on
    // https://msdn.microsoft.com/en-us/library/windows/desktop/ms724429.aspx
    // for Windows 10 detection?
    OSVERSIONINFO osvi;
    ZeroMemory(&osvi, sizeof osvi);
    osvi.dwOSVersionInfoSize = sizeof osvi;
    GetVersionEx(&osvi);
    lprintf("Windows %lu.%lu.%lu\n",
            osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);

    lprintf("\n");
}

static void
Setup(void)
{
    if (strlen(g_szLogFileName) != 0)
        return;

    if (REPORT_FILE) {
        // Figure out what the report file will be named, and store it away
        if(GetModuleFileNameA(NULL, g_szLogFileName, MAX_PATH))
        {
            LPSTR lpszDot;

            // Look for the '.' before the "EXE" extension.  Replace the extension
            // with "RPT"
            if((lpszDot = strrchr(g_szLogFileName, '.')))
            {
                lpszDot++;    // Advance past the '.'
                strcpy(lpszDot, "RPT");    // "RPT" -> "Report"
            }
            else
                strcat(g_szLogFileName, ".RPT");
        }
        else if(GetWindowsDirectoryA(g_szLogFileName, MAX_PATH))
        {
            strcat(g_szLogFileName, "EXCHNDL.RPT");
        }
    }
}



extern "C"
void
setLogFileName(const char *name)
{
  strncpy(g_szLogFileName, name, sizeof(g_szLogFileName));
}


extern "C"
void
dumpStack(const CONTEXT *pTargetContext)
{
  Setup();

  if (!g_hReportFile) {
      if (strcmp(g_szLogFileName, "-") == 0) {
          g_hReportFile = GetStdHandle(STD_ERROR_HANDLE);
          g_bOwnReportFile = FALSE;
      } else {
          g_hReportFile = CreateFileA(
              g_szLogFileName,
              GENERIC_WRITE,
              FILE_SHARE_READ | FILE_SHARE_WRITE,
              0,
              OPEN_ALWAYS,
              0,
              0
          );
          g_bOwnReportFile = TRUE;
      }
  }

  if (g_hReportFile) {
      SetFilePointer(g_hReportFile, 0, 0, FILE_END);

      lprintf("-------------------\n\n");

      SYSTEMTIME SystemTime;
      GetLocalTime(&SystemTime);
      char szDateStr[128];
      LCID Locale = MAKELCID(MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), SORT_DEFAULT);
      GetDateFormatA(Locale, 0, &SystemTime, "dddd',' MMMM d',' yyyy", szDateStr, _countof(szDateStr));
      char szTimeStr[128];
      GetTimeFormatA(Locale, 0, &SystemTime, "HH':'mm':'ss", szTimeStr, _countof(szTimeStr));
      lprintf("Error occurred on %s at %s.\n\n", szDateStr, szTimeStr);

      HANDLE hProcess = GetCurrentProcess();

      if (InitializeSym(hProcess, TRUE)) {

          dumpStack(hProcess, GetCurrentThread(), pTargetContext);

          if (!SymCleanup(hProcess)) {
              assert(0);
          }
      }

      FlushFileBuffers(g_hReportFile);
  }

}


extern "C"
void
crashHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
    static LONG cBeenHere = 0;

    if (InterlockedIncrement(&cBeenHere) == 1) {
        UINT fuOldErrorMode;

        fuOldErrorMode = SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

        Setup();

        if (REPORT_FILE) {
            if (!g_hReportFile) {
                if (strcmp(g_szLogFileName, "-") == 0) {
                    g_hReportFile = GetStdHandle(STD_ERROR_HANDLE);
                    g_bOwnReportFile = FALSE;
                } else {
                    g_hReportFile = CreateFileA(
                        g_szLogFileName,
                        GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        0,
                        OPEN_ALWAYS,
                        0,
                        0
                    );
                    g_bOwnReportFile = TRUE;
                }
            }

            if (g_hReportFile) {
                SetFilePointer(g_hReportFile, 0, 0, FILE_END);

                GenerateExceptionReport(pExceptionInfo);

                FlushFileBuffers(g_hReportFile);
            }
        } else {
            GenerateExceptionReport(pExceptionInfo);
        }

        SetErrorMode(fuOldErrorMode);
    }
    InterlockedDecrement(&cBeenHere);
}
