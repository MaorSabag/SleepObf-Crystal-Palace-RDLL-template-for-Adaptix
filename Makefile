CC_64=x86_64-w64-mingw32-gcc
NASM=nasm
CFLAGS=-DWIN_X64 -shared -Wall -Wno-pointer-arith -mno-stack-arg-probe -fno-zero-initialized-in-bss

all: bin/loader.x64.o bin/hooks.x64.o bin/pico.x64.o  bin/services.x64.o

bin:
	mkdir bin

bin/loader.x64.o: bin
	$(CC_64) $(CFLAGS) -c src/pico.c -o bin/pico.x64.o
	$(CC_64) $(CFLAGS) -c src/loader.c -o bin/loader.x64.o
	$(CC_64) $(CFLAGS) -c src/services.c -o bin/services.x64.o
	$(CC_64) $(CFLAGS) -c src/hooks.c -o bin/hooks.x64.o


clean:
	rm -f bin/*