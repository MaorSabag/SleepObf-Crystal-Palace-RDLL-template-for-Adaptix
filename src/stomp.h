#pragma once
#include <windows.h>
#include "tcg.h"

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect ( LPVOID, SIZE_T, DWORD, PDWORD );
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualFree ( LPVOID, SIZE_T, DWORD );
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryExA(LPCSTR, HANDLE, DWORD);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memset ( void *, int, size_t );


typedef struct _PICO {
	char data [ 4096 ];
	char code [ 16384 ];
} PICO;

typedef enum {
    rPICO,
    rDLL,
} RESOURCE_TYPE;

typedef struct _PICO_ARGS {
    PICO** pico_dst;
    IMPORTFUNCS *funcs;
    char *pico_src;
    const char *sacrificialDll;
} PICO_ARGS, *PPICO_ARGS;

typedef struct _DLL_ARGS {
    DLLDATA* dll_data;
    IMPORTFUNCS *funcs;
    char **dll_src;
    char **dll_dst;
    const char *sacrificialDll;
} DLL_ARGS, *PDLL_ARGS;

typedef struct _STOMP_ARGS {
    RESOURCE_TYPE resourceType;
    union {
        PICO_ARGS picoArgs;
        DLL_ARGS dllArgs;
    };
} STOMP_ARGS, *PSTOMP_ARGS;

BOOL Stomp( STOMP_ARGS stompArgs );

