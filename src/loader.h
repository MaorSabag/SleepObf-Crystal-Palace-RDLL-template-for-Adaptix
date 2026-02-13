void* GetExport(char* base, const char* name) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    
    // Safety check for empty export table
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD* names = (DWORD*)(base + exports->AddressOfNames);
    DWORD* functions = (DWORD*)(base + exports->AddressOfFunctions);
    WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* funcName = (char*)(base + names[i]);
        
        // Manual string comparison loop (Relocation-safe)
        const char* s1 = funcName;
        const char* s2 = name;
        while (*s1 && (*s1 == *s2)) {
            s1++;
            s2++;
        }

        if (*(unsigned char*)s1 == *(unsigned char*)s2) {
            return (void*)(base + functions[ordinals[i]]);
        }
    }
    return NULL;
}