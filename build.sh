CC="x86_64-w64-mingw32-gcc"
COPTS="-fno-ident -shared -Wall -Wno-pointer-to-int-cast
        -Os -Iinclude/ -Wl,--enable-stdcall-fixup
        -Wl,--entry=WinDivertDllEntry"
CLIBS="-lkernel32 -ladvapi32"
STRIP="x86_64-w64-mingw32-strip"
DLLTOOL="x86_64-w64-mingw32-dlltool"
CPU=amd64

mkdir -p "./build/"
$CC $COPTS -c dll/windivert.c -o dll/windivert.o
$CC $COPTS -o "build/WinDivert.dll" \
    dll/windivert.o dll/windivert.def -nostdlib $CLIBS

$CC -s -O2 -Iinclude/ src/packet.c \
    -o "build/packet.exe" -lWinDivert \
    -L"build/" \
    -fexec-charset=CP932