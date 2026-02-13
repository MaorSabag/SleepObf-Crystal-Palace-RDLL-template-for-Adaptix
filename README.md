# Crystal Palace RDLL Template for Adaptix C2

A Reflective DLL Loader for [Adaptix C2](https://github.com/Jekoie/Adaptix) built with [Crystal Palace](https://www.cobaltstrike.com/product/crystal-palace). Features IAT hooking, Ekko-style sleep obfuscation, and per-section memory permission management.

## What It Does

1. **Loads the Adaptix agent DLL** from a PIC blob via a custom reflective loader.
2. **XOR resource masking** — the DLL is XOR-encrypted at link time with a random 128-byte key (via Crystal Palace `generate`/`xor`/`preplen` directives). At runtime the loader decrypts it into a temporary buffer, maps it, then wipes and frees the cleartext copy.
3. **Hooks `Sleep` via IAT interception** — a PICO hijacks `GetProcAddress` at import resolution time so the DLL's `Sleep` call is transparently redirected.
4. **Ekko sleep obfuscation** — when `Sleep` is called, the entire DLL image is RC4-encrypted in memory via a 6-step `NtContinue` ROP chain (timer queue callbacks), then decrypted on wake.
5. **Per-section permission restore** — after decryption, a PE section walker applies the correct page protections (`.text` → `RX`, `.data` → `RW`, etc.) instead of blanket `RWX`, ensuring BOF compatibility.
6. **PIC cleanup** — after `go()` returns, the loader's own RWX allocation is wiped and freed.

## Project Structure

```
src/
  loader.c                # Main PIC — XOR-unmasks DLL, loads PICO, maps DLL, fixes permissions, calls entry point
  hooks.c                 # _Sleep hook → EkkoObf() + restore_section_permissions()
  pico.c                  # PICO — hooked GetProcAddress, setup_hooks(), set_image_info()
  services.c              # API resolution via hash walking
  loader.h                # PE export lookup helper
  tcg.h                   # Crystal Palace intrinsics & DLL loader structs
crystal_palace/
  specs/
    loader.spec           # Main PIC build spec (XOR masking, key generation)
    pico.spec             # PICO build spec (merges hooks.c, registers Sleep hook)
    services.spec         # Services build spec (API resolution via ror13/strings)
  link                    # Crystal Palace link wrapper
  piclink                 # Crystal Palace PIC link wrapper
  coffparse               # COFF parser utility
  disassemble             # Disassembler utility
  crystalpalace.jar       # Crystal Palace engine
  libtcg.x64.zip          # TCG runtime library
loader/
  include/
    Adaptix.h             # Adaptix C2 header
    Shellcode.h           # Auto-generated PIC blob as C hex array
  source/main/
    Exe.cc                # Final binary wrapper (EXE format)
    Dll.c                 # Final binary wrapper (DLL format)
    Svc.cc                # Final binary wrapper (service format)
  test/
    run.c                 # Test harness (loads and runs the PIC blob)
compile.go                # Build orchestrator (COFF → link → shellcode header → final binary)
Makefile                  # COFF object compilation
build/                    # Compiled COFF objects and PIC blob (agent.bin)
output/                   # Final compiled binaries (agent.exe, agent.dll)
```

## Prerequisites

- Crystal Palace toolchain (included in `crystal_palace/`)
- MinGW cross-compiler (`x86_64-w64-mingw32-gcc`)
- Go (for `compile.go` build orchestrator)
- Clang (`clang++` targeting `x86_64-w64-mingw32`) for final binary compilation
- Adaptix agent DLL (compiled with `&Sleep` instead of PEB walk — see below)

## Adaptix Source Change

Adaptix resolves `Sleep` via PEB walking (`GetSymbolAddress`), bypassing the IAT. For Crystal Palace hooking to work, change `ApiLoader.cpp`:

```diff
- ApiWin->Sleep = (decltype(Sleep)*)GetSymbolAddress(hKernel32Module, HASH_FUNC_SLEEP);
+ ApiWin->Sleep = &Sleep;
```

This forces a real IAT entry that `addhook` can intercept.

## Build

```bash
# Full build (COFF compile → Crystal Palace link → Shellcode.h → final binary)
go run compile.go -dll /path/to/agent.x64.dll -format exe -out agent

# Or step by step:
make clean && make all                                              # compile COFF objects
./crystal_palace/link crystal_palace/specs/loader.spec agent.dll agent.bin  # link PIC blob
go run compile.go -dll /path/to/agent.x64.dll -skip-coff -format exe       # skip COFF, build final binary
```

### compile.go flags

| Flag | Default | Description |
|------|---------|-------------|
| `-dll` | (required) | Path to the Adaptix agent DLL |
| `-format` | `exe` | Output format: `exe`, `dll`, or `svc` |
| `-out` | `agent` | Base name for the output binary |
| `-skip-coff` | `false` | Skip COFF compilation (reuse existing `.o` files) |
| `-skip-link` | `false` | Skip Crystal Palace link step (reuse existing `agent.bin`) |
| `-pic` | `agent.bin` | Path to pre-built PIC blob (used with `-skip-link`) |
| `-debug` | `false` | Compile with `-mconsole` instead of `-mwindows` |

## Test Harness

```bash
# Compile
x86_64-w64-mingw32-gcc -DWIN_X64 loader/test/run.c -o run.x64.exe -lws2_32

# Run
.\run.x64.exe build/agent.bin
```

## Resource Masking

The embedded DLL payload is never stored in cleartext inside the PIC blob. The `loader.spec` uses Crystal Palace directives to mask it at link time:

```ruby
generate $KEY 128       # random 128-byte XOR key

push $DLL
    xor $KEY            # XOR-encrypt the DLL
    preplen             # prepend its cleartext length
    link "dll"          # embed into the "dll" section

push $KEY
    preplen             # prepend the key length
    link "mask"         # embed into the "mask" section
```

At runtime, `loader.c` reads both sections as `RESOURCE` structs (length-prefixed blobs), XOR-decrypts the DLL into a temporary `VirtualAlloc` buffer, maps it into a properly laid-out image (`dll_dst`), then securely wipes and frees the temporary buffer.

## Compiler Flags

| Flag | Why |
|------|-----|
| `-mno-stack-arg-probe` | Avoids `___chkstk_ms` relocation (EkkoObf uses ~8.5 KB of stack) |
| `-fno-zero-initialized-in-bss` | Forces zero-init globals into `.data` instead of `.bss` (PIC can't resolve `.bss` relocations) |


## Credits

- Original Crystal Palace RDLL template by [Raphael Mudge](https://www.cobaltstrike.com)
- [Ekko](https://github.com/Cracked5pider/Ekko) sleep obfuscation by C5pider
- [Adaptix C2](https://github.com/Jekoie/Adaptix)
- [Kharon Agent](https://github.com/entropy-z/Kharon) for loader inspiration
- [h41th](https://github.com/h41th/Simple-Crystal-Palace-RDLL-template-for-Adaptix) for the original Crystal Palace loader template for Adaptix

## Disclaimer

This project is for educational and authorized red team use only. Obtain proper authorization before deploying.