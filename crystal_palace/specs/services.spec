x64:
    load "../../build/services.x64.o"
        merge

    mergelib "../../crystal_palace/libtcg.x64.zip"

    dfr "resolve" "ror13" "KERNEL32, NTDLL"
    dfr "resolve_ext" "strings"