# Requirements

You'll need an Android userland debugging environment and Python.

This is what we assume you have:

1.  A rooted Android device: Currently only ARM/ARM64 devices are supported.
    Make sure that your device uses jemalloc, some devices like the Nexus 9
    tablet still use dlmalloc.

    Root is needed so that you can debug processes through ptrace.

2.  Android Debug Bridge(adb): For shell access on the device.

    Download and setup instructions at:
    <https://developer.android.com/studio/command-line/adb.html>

3.  gdbserver:
    A gdbserver binary that you use to attach to a running process.

    You can find the ARM64 prebuilt binaries that work for us
    inside the bin/ directory.

4.  gdb with Python support:
    A gdb client compiled for ARM/ARM64 targets with Python support enabled.

    This is how we build ours:

        1. git clone http://android.googlesource.com/toolchain/gdb
        2. cd ./gdb/gdb-7.11
        3. mkdir build64; cd build64
        4. ../configure --program-prefix=aarch64-eabi-linux- --target=aarch64-eabi-linux --disable-werror --with-python
        5. make
        6. make install

    If you use Ubuntu you can get the gdb-multiarch package:

        apt-get install gdb-multiarch

5.  (optional) pyrsistence:
    You'll need this if you want to use the heap snapshot feature of shadow.

    Thankfully, it is very easy to build and install:
    <https://github.com/huku-/pyrsistence>

# Usage Example

Start an adb shell and attach gdbserver to your target process.

    adb forward tcp :5039 :5039

    bullhead:/data/local/tmp # ./gdbserver :5039 --attach 19663
    Attached; pid = 19663
    Listening on port 5039

Connect your gdb client to gdbserver.

    (gdb) target remote :5039
    ...
    Reading /system/bin/linker from remote target...
    0xecfc9528 in __epoll_pwait () from target:/system/lib/libc.so
    (gdb)

Load the gdb_driver.py file. Once the driver is loaded you have
access to shadow's commands.

    (gdb) source /Users/vats/repos/shadow/gdb_driver.py

Use the jeparse command to parse the heap.

    (gdb) jeparse
    [shadow] Detecting Android version...
    [shadow] Using Android 7 32 bit configuration.
             (/Users/vats/repos/shadow/cfg/android7_32.cfg)
    [shadow] parsing structures from memory...
    [shadow] structures parsed

At this point you can:

1.  Examine the heap using shadow's available commands.

    Use "jehelp" to view a list of all the commands and
    their usage:

        (gdb) jehelp
        [shadow] De Mysteriis Dom jemalloc
        [shadow] shadow v2.0
        [shadow] Android v7 (Aarch64)

        [shadow] jemalloc-specific commands:
        [shadow]   jechunks                : dump info on all available chunks
        [shadow]   jearenas                : dump info on jemalloc arenas
        ...

2.  Run your own scripts that access the parsed heap object.

        (gdb) source /Users/vats/repos/shadow/examples/android_script_example.py
        libskia.so loaded at 0x717b1fd000
        Searching for 0xc0 sized regions that point to libskia.so + 0x5528d8
        Found 6 regions.
          - 0x715f88b400 (busy)
          - 0x715f88b580 (busy)
          - 0x715f88bd00 (busy)
          - 0x715f88bdc0 (busy)
          - 0x715f88be80 (busy)
          - 0x715ee66240 (busy)

3.  Store a heap snapshot.

        (gdb) jestore /tmp/heap_snapshot1

    You can parse the snapshot later by either using shadow as a Python script:

        $ python shadow.py /tmp/heap_snapshot1 jeruns -c
        * arena[0]
        region size    run address     run size    usage
        ------------------------------------------------------
        0x8            0x71604f9000    0x1000      204/512
        0x10           0x715ef76000    0x1000      161/256
        0x20           0x715effb000    0x1000      71/128
        0x30           0x715f65c000    0x3000      255/256
        ...

    or by using your own scripts:

        $ python examples/android_snapshot_example.py /tmp/heap_snapshot1
        chunk @ 0x715e200000 has 45 runs.
        chunk @ 0x715ee00000 has 130 runs.
        chunk @ 0x715f600000 has 99 runs.
        ...

