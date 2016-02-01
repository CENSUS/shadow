shadow :: De Mysteriis Dom Firefox
==================================

A new, extended (and renamed ;) version of the Firefox/jemalloc heap
exploitation swiss army knife.

**shadow** has been tested with the following:

* Windows 8.1 x86-64
* Windows 7 SP1 x86 and x86-64
* [WinDBG 6.3.9600.17200]
(https://msdn.microsoft.com/en-us/windows/hardware/hh852365.aspx)
x86 (since Firefox stable is x86-only currently)
* [pykd version 0.3.0.36](https://pykd.codeplex.com/releases/view/618995)
* Many different Firefox releases, but extensively with:
[31.7.0-esr](http://ftp.mozilla.org/pub/mozilla.org/firefox/releases/31.7.0esr/),
[35.0.1](http://ftp.mozilla.org/pub/mozilla.org/firefox/releases/35.0.1/),
[36.0.1](http://ftp.mozilla.org/pub/mozilla.org/firefox/releases/36.0.1/),
[38.0.5](http://ftp.mozilla.org/pub/mozilla.org/firefox/releases/38.0.5/),
[39.0](http://ftp.mozilla.org/pub/mozilla.org/firefox/releases/39.0/),
[40.0](http://ftp.mozilla.org/pub/mozilla.org/firefox/releases/40.0/),
[43.0](http://ftp.mozilla.org/pub/mozilla.org/firefox/releases/43.0/).
[44.0](http://ftp.mozilla.org/pub/mozilla.org/firefox/releases/44.0/).

*Note: If you work with a Firefox version older than 36.0 use the mozjs branch!*

Installation
------------

At first you need to setup WinDBG with [Mozilla's symbol server]
(https://developer.mozilla.org/en/docs/Using_the_Mozilla_symbol_server).
You also need to install [pykd version 0.3.0.36]
(https://pykd.codeplex.com/releases/view/618995). Then copy the **shadow**
directory you have cloned from GitHub to some path (e.g. *C:\\tmp\\*).

I have also added an example WinDBG initialization script at
"aux/windbg-init.cmd". Place it at *C:\\tmp\\* and start WinDBG with
*windbg.exe -c "$$>< C:\tmp\windbg-init.cmd"*.

Finally, from within WinDBG issue the following commands:

```
!load pykd.pyd
!py c:\\tmp\\shadow\\pykd_driver help

[shadow] De Mysteriis Dom Firefox
[shadow] v1.0b

[shadow] jemalloc-specific commands:
[shadow]   jechunks                : dump info on all available chunks
[shadow]   jearenas                : dump info on jemalloc arenas
[shadow]   jerun <address>         : dump info on a single run
[shadow]   jeruns [-cs]            : dump info on jemalloc runs
[shadow]                                 -c : current runs only
[shadow]                    -s <size class> : runs for the given size class only
[shadow]   jebins                  : dump info on jemalloc bins
[shadow]   jeregions <size class>  : dump all current regions of the given size class
[shadow]   jesearch [-cfqs] <hex>  : search the heap for the given hex dword
[shadow]                                 -c : current runs only
[shadow]                                 -q : quick search (less details)
[shadow]                    -s <size class> : regions of the given size only
[shadow]                                 -f : search for filled region holes)
[shadow]   jeinfo <address>        : display all available details for an address
[shadow]   jedump [filename]       : dump all available jemalloc info to screen (default) or file
[shadow]   jeparse                 : parse jemalloc structures from memory
[shadow] Firefox-specific commands:
[shadow]   nursery                 : display info on the SpiderMonkey GC nursery
[shadow]   symbol [-vjdx] <size>   : display all Firefox symbols of the given size
[shadow]                                 -v : only class symbols with vtable
[shadow]                                 -j : only symbols from SpiderMonkey
[shadow]                                 -d : only DOM symbols
[shadow]                                 -x : only non-SpiderMonkey symbols
[shadow]   pa <address> [<length>] : modify the ArrayObject's length (default new length 0x666)
[shadow] Generic commands:
[shadow]   version                 : output version number
[shadow]   help                    : this help message
```

If you don't see the above help message you have done something wrong ;)

Usage
-----

When you issue a jemalloc-specific command for the first time, **shadow** parses
all jemalloc metadata it knows about and saves them to a Python pickle file.
Subsequent commands use this pickle file instead of parsing the metadata from
memory again in order to be faster.

When you know that the state of jemalloc metadata has changed (for example when
you have made some allocations or have triggered a garbage collection), use the
**jeparse** command to re-parse the metadata and re-create the pickle file.

Support for symbols
-------------------

*Note: This feature is currently Windows-only!*

The **symbol** command allows you to search for SpiderMonkey and DOM classes (and
structures) of specific sizes. This is useful when you're trying to exploit
use-after-free bugs, or when you want to position interesting victim objects to
overwrite/corrupt.

In the "aux" directory you can find a small PDB parsing utility named **symhex**.
Run it on "xul.pdb" to generate the Python pickle file that **shadow** expects in
the "pdb" directory (as "pdb/xul-*VERSION*.pdb.pkl"). Before running **symhex** make
sure you have registered "msdia90.dll"; for example on my Windows 8.1 x86-64
installation I did that with

*regsvr32 "c:\Program Files (x86)\Common Files\Microsoft Shared\VC\msdia90.dll"*

from an Administrator prompt. You also need the "comtypes" Python module; install
[pip](https://pip.pypa.io/en/latest/installing.html) and then do
*pip install comtypes*.

In order to get "xul.pdb" you have to setup WinDBG with [Mozilla's symbol server]
(https://developer.mozilla.org/en/docs/Using_the_Mozilla_symbol_server).

Design
------

I initially re-designed **unmask_jemalloc** with a modular design to support all
three main debuggers and platforms (WinDBG, GDB and LLDB). I renamed the tool to
**shadow** when I added Firefox/Windows/WinDBG-only features.

The following is an overview of the new design (read the arrows as "imports"). The
goal is, obviously, to have all debugger-dependent code in the *_driver and *_engine
modules.

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

Feel free to fork and issue pull requests!

