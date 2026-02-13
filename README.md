# Crystal Palace RDLL Template for Adaptix C2

A Reflective DLL Loader for [Adaptix C2](https://github.com/Jekoie/Adaptix) built with [Crystal Palace](https://www.cobaltstrike.com/product/crystal-palace). Features IAT hooking, Ekko-style sleep obfuscation, and per-section memory permission management.

## What It Does

1. **Loads the Adaptix agent DLL** from a PIC blob via a custom reflective loader.
2. **Hooks `Sleep` via IAT interception** — a PICO hijacks `GetProcAddress` at import resolution time so the DLL's `Sleep` call is transparently redirected.
3. **Ekko sleep obfuscation** — when `Sleep` is called, the entire DLL image is RC4-encrypted in memory via a 6-step `NtContinue` ROP chain (timer queue callbacks), then decrypted on wake.
4. **Per-section permission restore** — after decryption, a PE section walker applies the correct page protections (`.text` → `RX`, `.data` → `RW`, etc.) instead of blanket `RWX`, ensuring BOF compatibility.
5. **PIC cleanup** — after `go()` returns, the loader's own RWX allocation is wiped with `SecureZeroMemory` and freed.

## Project Structure

```
src/
  loader.c      # Main PIC — loads PICO, loads DLL, fixes permissions, calls entry point
  hooks.c       # _Sleep hook → EkkoObf() + restore_section_permissions()
  pico.c        # PICO — hooked GetProcAddress, setup_hooks(), set_image_info()
  services.c    # API resolution via hash walking
  loader.h      # PE parsing helpers
  tcg.h         # Crystal Palace intrinsics
loader.spec     # Main PIC build spec
pico.spec       # PICO build spec (merges hooks.c, registers Sleep hook)
services.spec   # Services build spec
demo/src/run.c  # Test harness (loads and runs the PIC blob)
```

## Prerequisites

- Crystal Palace toolchain (`./link`, `./piclink`, `./coffparse`, `libtcg.x64.zip`)
- MinGW cross-compiler (`x86_64-w64-mingw32-gcc`)
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
# Compile COFF objects
make clean && make all

# Link with Crystal Palace
./link loader.spec /path/to/agent.x64.dll agent.bin
```

## Test Harness

```bash
# Compile
x86_64-w64-mingw32-gcc -DWIN_X64 demo/src/run.c -o run.x64.exe -lws2_32

# Run
.\run.x64.exe agent.bin
```

## Compiler Flags

| Flag | Why |
|------|-----|
| `-mno-stack-arg-probe` | Avoids `___chkstk_ms` relocation (EkkoObf uses ~8.5 KB of stack) |
| `-fno-zero-initialized-in-bss` | Forces zero-init globals into `.data` instead of `.bss` (PIC can't resolve `.bss` relocations) |

## Blog

See [blog/sleeping-beauty.md](blog/sleeping-beauty.md) for the full writeup covering every bug, fix, and design decision.

## Credits

- Original Crystal Palace RDLL template by [Raphael Mudge](https://www.cobaltstrike.com)
- [Ekko](https://github.com/Cracked5pider/Ekko) sleep obfuscation by C5pider
- [Adaptix C2](https://github.com/Jekoie/Adaptix)

## Disclaimer

This project is for educational and authorized red team use only. Obtain proper authorization before deploying.