shadow :: De Mysteriis Dom jemalloc
===================================

**shadow** is a jemalloc heap exploitation framework. It has been designed
to be agnostic of the target application that uses jemalloc as its heap
allocator (be it Android's libc, Firefox, FreeBSD's libc, standalone jemalloc,
or whatever else). The current version (2.0) has been tested extensively with
the following targets:

* Android 6-9 libc (ARM32 and ARM64)
* Firefox (x86 and x86-64) on Windows and Linux

Apart from the tool's source code, this repository also includes documentation on
[setting up an Android userland debugging environment](https://github.com/CENSUS/shadow/blob/master/docs/android_quickstart.md)
for utilizing shadow, a
[quick overview of Android's jemalloc structures](https://github.com/CENSUS/shadow/blob/master/docs/android_heap.md)
using shadow, and some notes on how double, unaligned and arbitrary free() bugs
[behave on Android's jemalloc](https://github.com/CENSUS/shadow/blob/master/docs/android_free_attacks.md).


## Usage

When you issue a jemalloc-specific command for the first time, **shadow** parses
all jemalloc metadata it knows about and saves them to a Python pickle file.
Subsequent commands use this pickle file instead of parsing the metadata from
memory again in order to be faster.

When you know that the state of jemalloc metadata has changed (for example when
you have made some allocations or have triggered a garbage collection), use the
**jeparse** command to re-parse the metadata and re-create the pickle file.


## Android Installation

First step is to install [pyrsistence](https://github.com/huku-/pyrsistence)
on your host machine.

On a rooted device do the following:

```
host$ adb shell
phone$ su root
phone# ps -e
```

From the output of *ps* select a process, for example
*com.google.process.gapps*:

```
...
u0_a19    4679  3214  1668980 69216 SyS_epoll_ 7fa5f41430 S com.google.process.gapps
...
phone$ cd /data/local/tmp
phone$ ./gdbserver64 :5039 --attach 4679
```

You can find GDB server binaries for ARM32 and ARM64 in the "bin" directory.
Or, if you don't trust us, do:

```
host$ git clone http://android.googlesource.com/toolchain/gdb
host$ cd ./gdb/gdb-7.11
host$ mkdir build64; cd build64
host$ ../configure --program-prefix=aarch64-eabi-linux- --target=aarch64-eabi-linux --disable-werror
host$ make
host$ sudo make install
```

Then on the host machine do:

```
host$ adb forward tcp:5039 tcp:5039
host$ aarch64-eabi-linux-gdb
(gdb) target remote :5039
(gdb) source /dir/with/shadow/gdb_driver.py
(gdb) jeparse -c /dir/with/shadow/cfg/android7_64.cfg
(gdb) jeruns -c
```

Sometimes GDB server stops listening if you take too long to issue the
*target remote :5039* command. So if you see weird errors when you issue
the *jeparse* command, just start from the beginning.


## Windows/Firefox Installation

**shadow** for Windows/Firefox has been tested with the following:

* Windows 8.1 and 10 x86-64
* Windows 7 SP1 x86 and x86-64
* Various versions of WinDBG
* [pykd version 0.3.2.8](https://pykd.codeplex.com/releases/view/631449)
* Many different Firefox releases (both x86-64 and x86), including the latest
stable one ([55.0](http://ftp.mozilla.org/pub/mozilla.org/firefox/releases/55.0/))

*Note: If you work with a Firefox version older than 36.0 use the mozjs branch!*

At first you need to setup WinDBG with [Mozilla's symbol server]
(https://developer.mozilla.org/en/docs/Using_the_Mozilla_symbol_server).
You also need to install pykd. Then copy the **shadow** directory you have
cloned from GitHub to some path (e.g. *C:\\tmp\\*).

You can also find an example WinDBG initialization script in the file
"windbg-init.cmd". Place it at *C:\\tmp\\* and start WinDBG with
*windbg.exe -c "$$>< C:\tmp\windbg-init.cmd"*.

Finally, from within WinDBG issue the following commands:

```
!load pykd.pyd
!py c:\\tmp\\shadow\\pykd_driver help

[shadow] De Mysteriis Dom jemalloc
[shadow] shadow v2.0
[shadow] Firefox v56.0a1 (x86-64)

[shadow] jemalloc-specific commands:
[shadow]   jechunks                : dump info on all available chunks
[shadow]   jearenas                : dump info on jemalloc arenas
[shadow]   jerun [-m] <address>    : dump info on a single run
[shadow]                                 -m : map content preview to metadata
[shadow]   jeruns [-cs]            : dump info on jemalloc runs
[shadow]                                 -c : current runs only
[shadow]                    -s <size class> : runs for the given size class only
[shadow]   jebins                  : dump info on jemalloc bins
[shadow]   jebininfo               : dump info on bin sizes 
[shadow]   jesize2bin              : convert size to bin index
[shadow]   jeregions <size class>  : dump all runs that host the regions of
[shadow]                             the given size class
[shadow]   jesearch [-cs] <hex>    : search the heap for the given hex dword
[shadow]                                 -c : current runs only
[shadow]                    -s <size class> : regions of the given size only
[shadow]   jeinfo <address>        : display all available details for an address
[shadow]   jedump [path]           : store the heap snapshot to the current
[shadow]                             working directory or to the specified path
[shadow]   jestore [path]          : jedump alias
[shadow]   jetcaches               : dump info on all tcaches
[shadow]   jetcache [-bs] <tid>    : dump info on single tcache
[shadow]                    -b <bin index>  : info for the given bin index only
[shadow]                    -s <size class> : info for the given size class only
[shadow]   jeparse [-crv]           : parse jemalloc structures from memory
[shadow]                   -c <config file> : jemalloc target config file
[shadow]                                 -r : read content preview
[shadow]                                 -v : produce debug.log
[shadow] Firefox-specific (pykd only) commands:
[shadow]   nursery                 : display info on the SpiderMonkey GC nursery
[shadow]   symbol [-vjdx] <size>   : display all Firefox symbols of the given size
[shadow]                                 -v : only class symbols with vtable
[shadow]                                 -j : only symbols from SpiderMonkey
[shadow]                                 -d : only DOM symbols
[shadow]                                 -x : only non-SpiderMonkey symbols
[shadow]   pa <address> [<length>] : modify the ArrayObject's length (default new length 0x666)
[shadow] Android-specific commands:
[shadow]   jefreecheck [-bm]                : display addresses that can be passed to free()
[shadow]                     -b <bin index> : display addresses that will be freed to
[shadow]                                      the tcache bin of <bin index>
[shadow]                          -m <name> : only search this specific module
[shadow] Generic commands:
[shadow]   jeversion               : output version number
[shadow]   jehelp                  : this help message
```

If you don't see the above help message you have done something wrong ;)

### Support for symbols

*Note: This feature is currently Firefox/Windows-only!*

The **symbol** command allows you to search for SpiderMonkey and DOM classes (and
structures) of specific sizes. This is useful when you're trying to exploit
use-after-free bugs, or when you want to position interesting victim objects to
overwrite/corrupt.

In shadow's main directory you can find two small PDB parsing utilities, **symhex.py**
and **pdbdy.py** (faster). Run them on "xul.pdb" to generate the Python pickle file that
**shadow** expects in the "pdb" directory (as "pdb/xul-*VERSION*.pdb.pkl"). Before running
them make sure you have registered "msdia90.dll"; for example on Windows 8.1 x86-64 you
can do that with:

*regsvr32 "c:\Program Files (x86)\Common Files\Microsoft Shared\VC\msdia90.dll"*

from an Administrator prompt. You also need the "comtypes" Python module; install
[pip](https://pip.pypa.io/en/latest/installing.html) and then do
*pip install comtypes*.

In order to get "xul.pdb" you have to setup WinDBG with [Mozilla's symbol server]
(https://developer.mozilla.org/en/docs/Using_the_Mozilla_symbol_server).


## Design

**unmask_jemalloc** was initially re-designed with a modular design to support
all three main debuggers and platforms (WinDBG, GDB and LLDB). The tool was
renamed to **shadow** when Firefox/Windows/WinDBG-only features were added.

The following is an overview of the new design (read the arrows as
"imports"). The goal is, obviously, to have all debugger-dependent code in the
*_driver and *_engine modules.

    ---------------------------------------------------------------------------------------

                                                        debugger-required frontend (glue)


    +------------+     +-------------+     +-------------+
    | gdb_driver |     | lldb_driver |     | pykd_driver |
    +------------+     +-------------+     +-------------+
          ^                   ^                   ^
          |                   |                   |
    ------+-------------------+-------------------+----------------------------------------
          |                   |                   |   
          |                   +--------+          |
          +------------------------    |    +-----+        core logic (debugger-agnostic)
                                  |    |    |
                                  |    |    |
                               +-----------------+
      +------+                 |                 |
      |      |---------------> |      shadow     |<-----+
      | util |        +------> |                 |      |
      |      |        |        +-----------------+      |
      +------+        |          ^  ^     ^    ^        |
        | | |         |          |  |     |    |        |   +--------+
        | | |   +-----+----------+  |     +----+--------+---| symbol |
        | | |   |     |             |          |        |   +--------+
      +-+ | |   |  +----------+     |          |        |   +---------+
      |   | |   |  | jemalloc |     |          +--------+---| nursery |
      |   | |   |  +----------+     |                   |   +---------+
      |   | |   |   ^    ^   ^      |                   |
      |   | |   |   |    |   |      |                   |
      |   | |   |   |    |   +------+--------+          |
      |   | |   |   |    |          |        |          |
      |   | +---+---+----+----------+--------+-----+    |
      |   |     |   |    |          |        |     |    |
      |   +-----+---+----+----+     |        |     |    |
      |         |   |    |    |     |        |     |    |
    --+---------+---+----+----+-----+--------+-----+----+----------------------------------
      |         |   |    |    |     |        |     |    |
      |         |   |    |    |     |        |     |    |       debugger-dependent APIs
      |         |   |    |    |     |        |     |    |
      |         |   |    |    |     |        |     |    |
      |         |   |    |    v     |        |     v    |
      |  +------------+  |  +-------------+  |  +-------------+
      +->| gdb_engine |  +--| lldb_engine |  +--| pykd_engine |
         +------------+     +-------------+     +-------------+
               ^                   ^                   ^
               |                   |                   |
           +---+         +---------+   +---------------+
           |             |             |
           |             |             |
    -------+-------------+-------------+---------------------------------------------------
           |             |             |
           |             |             |                        debugger-provided backend
           |             |             |
           |             |             |
        +-----+      +------+      +------+
        | gdb |      | lldb |      | pykd |
        +-----+      +------+      +------+

    ---------------------------------------------------------------------------------------
