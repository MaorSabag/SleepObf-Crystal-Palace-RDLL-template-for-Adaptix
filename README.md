# Crystal Palace RDLL Template for Adaptix C2

A Crystal Palace-based reflective loader pipeline for Adaptix agents, with runtime API hook support, sleep obfuscation, resource masking, and section-aware memory protection restoration.

## Purpose

This repository contains the loader side of the integration:

1. Build Adaptix agent wrappers (`exe`, `dll`, `svc`) from a generated PIC blob.
2. Hook selected APIs through IAT-compatible call paths.
3. Obfuscate in-memory image during sleep cycles.
4. Restore section permissions after wake-up for safer execution.
5. Keep payloads masked in the embedded resources until runtime.

This repository does not contain the full Adaptix source tree. Adaptix-side compatibility patches are tracked in a separate fork/branch.

## Project Layout

```text
compile.go                 # Primary build orchestration entry point
Makefile                   # COFF build and utility targets
src/                       # Core PIC loader/hook logic
loader/                    # EXE/DLL/SVC wrappers and includes
src_service/               # Adaptix builder extender plugin integration
crystal_palace/            # Crystal Palace linker/spec toolchain assets
bin/                       # Build artifacts
demo/                      # Optional demo assets
```

## Prerequisites

- Crystal Palace toolchain (included in `crystal_palace/`)
- MinGW cross-compiler (`x86_64-w64-mingw32-gcc`)
- Go toolchain (for `compile.go` and service plugin code)
- Clang targeting `x86_64-w64-mingw32` for final wrapper build


### `compile.go` flags

| Flag | Default | Description |
|------|---------|-------------|
| `-dll` | required | Path to Adaptix agent DLL input |
| `-format` | `exe` | Output format: `exe`, `dll`, `svc` |
| `-out` | `agent` | Output base filename |
| `-skip-coff` | `false` | Skip COFF compilation |
| `-skip-link` | `false` | Skip Crystal Palace link stage |
| `-pic` | `agent.bin` | Prebuilt PIC path when skipping link |
| `-debug` | `false` | Use console subsystem (`-mconsole`) |

## Adaptix Source Compatibility

The Adaptix-side changes are maintained in this branch:

- https://github.com/MaorSabag/AdaptixC2/tree/Compatible-with-StealthPalace

If you want to port compatibility manually from `Adaptix-Framework/AdaptixC2:main`, apply the following commits in order.

### Manual port commits (ordered)

1. `5e2af22` - Restructure SMB Connector from Polling to Event-Driven Blocking  
   https://github.com/MaorSabag/AdaptixC2/commit/5e2af220bd407e72d7349f9d726ad6a99c0bd38d
2. `4d977de` - Improved the improvement  
   https://github.com/MaorSabag/AdaptixC2/commit/4d977dee51dc7dca9ce3ec43af42e52b94305ac1
3. `c463915` - Minor fixes  
   https://github.com/MaorSabag/AdaptixC2/commit/c463915249ace510e9874d28911b33c50687855e
4. `2b7c3c7` - Final result  
   https://github.com/MaorSabag/AdaptixC2/commit/2b7c3c76e5a06c7f12d00955bfe3fe7b04c6a978
5. `ac0ab9e` - AdaptixServer changes  
   https://github.com/MaorSabag/AdaptixC2/commit/ac0ab9ebbdf0d8d4b9831bddd5386d20b3e1b19e

### What these commits cover

- SMB connector transition from polling to event-driven/overlapped flow.
- Connector and agent-side API/interface alignment for response handling.
- Follow-up fixes for connector timing and stability.
- Consolidated compatibility edits across loader-facing agent code.
- Adaptix server-side post-build hook changes for StealthPalace wrapping.

### Likely Adaptix files touched during manual port

- `AdaptixServer/teamserver/evt/evt_types.go`
- `AdaptixServer/teamserver/extender/ts_agent_builder.go`
- `AdaptixServer/template/implant/src/core/ApiLoader.cpp`
- `AdaptixServer/template/implant/src/core/ApiLoader.h`
- `AdaptixServer/template/implant/src/core/ApiDefines.h`
- `AdaptixServer/template/implant/src/core/ConnectorSMB.cpp`
- `AdaptixServer/template/implant/src/core/ConnectorSMB.h`
- `AdaptixServer/template/implant/src/core/MainAgent.cpp`
- `AdaptixServer/template/implant/src/core/Pivotter.cpp`
- `AdaptixServer/template/implant/src/core/Pivotter.h`

### Optional git flow for manual application

```bash
git remote add stealthpalace https://github.com/MaorSabag/AdaptixC2.git
git fetch stealthpalace Compatible-with-StealthPalace

git cherry-pick 5e2af220bd407e72d7349f9d726ad6a99c0bd38d
git cherry-pick 4d977dee51dc7dca9ce3ec43af42e52b94305ac1
git cherry-pick c463915249ace510e9874d28911b33c50687855e
git cherry-pick 2b7c3c76e5a06c7f12d00955bfe3fe7b04c6a978
git cherry-pick ac0ab9ebbdf0d8d4b9831bddd5386d20b3e1b19e
```

If a commit conflicts because upstream changed nearby code, use the commit link as the source of truth and port the same logic manually.

## Resource Masking Model

The agent DLL is masked in `loader.spec` at link time using a generated XOR key and embedded as resources. At runtime, `src/loader.c` restores the DLL into a temporary buffer, maps it into the destination image, then wipes and frees the temporary cleartext allocation.

## Compiler Notes

- `-mno-stack-arg-probe`: avoids `___chkstk_ms` relocation issues in deep obfuscation paths.
- `-fno-zero-initialized-in-bss`: keeps globals in relocatable sections for PIC usage.

## Demo

https://github.com/user-attachments/assets/240e1b2d-c8f1-4e70-865d-872f04e192a9

## Credits

- Crystal Palace RDLL approach by Raphael Mudge
- Ekko research by C5pider
- Adaptix C2 framework by Adaptix-Framework
- Kharon Agent inspiration for loader patterns
- Original Adaptix Crystal Palace template by h41th

## Disclaimer

For authorized security testing and red-team operations only. Ensure you have explicit permission before use.
