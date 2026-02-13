x64:
    load "bin/services.x64.o"
        merge

    mergelib "libtcg.x64.zip"

    dfr "resolve" "ror13" "KERNEL32, NTDLL"
    dfr "resolve_ext" "strings"