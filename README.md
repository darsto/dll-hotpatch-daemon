# DLL Hotpach Daemon

This is a daemon for triggering remote re-compilation and runtime re-injecting of a DLL into an x86 process. Write DLLs potentially on a Linux machine, seamlessly compile and run them on a Windows box. This includes a GDB wrapper that essentially acts as a gdbserver. Hot-patch DLLs while debugging, inspect the bugs as they come. Or attach/detach on demand.

**WARNING! The daemon is capable of executing any shell commands received on a TCP socket**

## Basic usage:

Windows:
```bash
cd w:/path/to/mylib
./build/hookdaemon.exe -e c:/path/to/Target.exe -d w:/path/to/mylib/mylib.dll
```

Linux:
```bash
nc $IP 61171 <<< "gcc -o mylib.dll mylib.c -shared -fPIC -Wl,--subsystem,windows -static-libgcc"
nc $IP 61171 <<< "hook"
```

The above will compile mylib.dll in the hookdaemon's current directory [^1], then the special `hook` command will either start the exe with mylib.dll injected, or if the exe is already running it will first detach the previous dll, then attach the new one.

Any DLL can be detached and re-attached. If the DLL exports a `Deinit` function, it will be first called before unloading. If the DLL is critical to program execution and can't be unloaded at any time, then it's the DLL's responsibility to put the application into safe-to-unload state before actually unloading. This functionality is implemented in [patchmem](https://github.com/darsto/patchmem) runtime code patching library (for x86 32-bit).

All regular commands have their output sent back (streamed) over the same connection, which is always terminated once the command has finished. A single connection can run multiple commands if they're chained with ; or &&, etc. stderr and stdout are combined.

## GDB server / debugging

```bash
nc $IP 61171 <<< "gdb $PORT_TO_START_GDBSERVER_ON"
```

`gdb` is another special command parsed by the daemon itself. It returns immediately and gdbserver is started on given port. Once a connection is made, the target process will be started if it's not running yet, then a gdb.exe process will start and attach to the target process. If the target process had to be started in the previous step, it would be started with CREATE_SUSPENDED to make sure the gdb gets a chance to break at any main() or another entry point.

None of the GDBserver versions I tried could be seamlessly used from a Linux machine. It's recommended to use an improved Windows GDB instead of the original one: https://github.com/ssbssa/gdb which at least implement the mi-async mode (placing interrupts while running). And GDB from that release works fine, but GDBServer seems far off. On-demand interrupts are sometimes not getting a response message and breakpoints are not getting triggered. But the just local GDB works fine, so this daemon runs GDB and makes it a GDBServer by listening to TCP socket and just forwarding all commands. Some input commands need to be modified to convert from remote debugging (what the client thinks it does) to local debugging (what is actually done to gdb).

## Hardcoded values

The daemon currently has one feature hardcoded for a specific target exe. In exe.c in exe_start(), there is a hardcoded address of IAT entry (Import Address Table entry) that's filled with zeroes before it's actually processed by the exe. This is to prevent the executable from loading a DLL as a depedency, as we want to inject that DLL ourselves.

Look for the comment: `/* remove the original DLL dependency */`. The IAT entry is filled with zeroes because it happens to be the last entry in the table and we're effectively making the table one element shorter. It's not always the case - if that entry is not at the end, it would be necessary to disable it some other way. E.g. the DllMain() of that library could be made to exit immediately if there's some environment variable set (or some value in memory is set). Altenatively, a temporary DLL that doesn't do anything could be created with the same name.

## Building

Simply run `make`. There's no dependencies besides winsock2. This was tested under 32-bit MinGW.

## VSCode integration

The `samples` directory contains scripts and .json files meant to directly integrate this daemon with VSCode.

[^1]: mylib.dll can be always recompiled in place because the daemon will make a copy of it before attaching. The original mylib.dll file will never be directly injected into the executable.
