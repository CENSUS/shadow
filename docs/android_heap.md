In this document we explore Android's jemalloc structures using shadow.

A simplified view of the heap is presented here. The intention of this
document is to get you started with jemalloc structures and shadow's commands.

jemalloc's source code and the following material can help you build a
more complete view:

- XXX

# Memory Organization Structures

Allocations returned by jemalloc are divided into three size classes:
  - Small
  - Large
  - Huge

There are three important memory organization structures in jemalloc:
  - Chunks
  - Runs
  - Regions

## Chunks

Memory returned by the OS is divided into chunks.

All the metadata about the chunk itself and the allocations it contains
are stored at the start of the chunk (i.e. there are no inline metadata).

You can view the heap's chunks by using the "jechunks" command:

    (gdb) jechunks
    addr            arena           no_runs
    -------------------------------------------
    0x715da00000    0x717a402200    10
    0x715ee00000    0x717a402200    137
    0x715f600000    0x717a402200    129
    0x715f800000    0x717a402200    125
    ...

Chunks in Android have the following sizes:

|          |  32-bit |   64-bit |
|----------+---------+----------|
| Android6 | 0x40000 |  0x40000 |
| Android7 | 0x80000 | 0x200000 |

Chunks are further divided into runs.

You can view how a chunk is divided into runs with the
"jechunk" command:

    (gdb) jechunk 0x715da00000
    addr            info                  size        usage
    -----------------------------------------------------------
    0x715da00000    headers               0xc000      -
    0x715da0c000    small run (0x400)     0x1000      4/4
    0x715da0d000    small run (0x400)     0x1000      2/4
    0x715da0e000    small run (0x200)     0x1000      8/8
    ...

You can also get a list of all the jemalloc runs, ordered by
ascending addresses, using the "jeruns" command:

    (gdb) jeruns
            run_addr        run_size    region_size    no_regions    no_free
    ----------------------------------------------------------------------------
    1       0x715da0c000    0x1000      0x400          4             0
    2       0x715da0d000    0x1000      0x400          4             2
    3       0x715da0e000    0x1000      0x200          8             0
    4       0x715da0f000    0x1000      0x200          8             0
    ...
    13      0x715ee32000    0x5000      -              -             -    (1)
    14      0x715ee37000    0x3000      0xc0           64            0    (2)
    ...


A run can be used to host either one large allocation or
a number of small allocations.

The run at (1) is a large run; it is used to host one large allocation
of size 0x5000.

The run at (2) is a small run; it hosts 64 small allocations(regions)
each one of size 0xc0.

## Regions

Runs that host small allocations are divided into regions. A region is
synonymous to a small allocation.

Regions have their own size classes and each class is represented by a "bin".
You can view these size classes by using the "jebininfo" command:

    (gdb) jebininfo
    index    region_size    run_size    no_regions
    --------------------------------------------------
    0        0x8            0x1000      512
    1        0x10           0x1000      256
    2        0x20           0x1000      128
    3        0x30           0x3000      256
    ...


Regions (small allocations) are the most common allocations and the
ones you'll most likely need to manipulate/control/overflow.

Each small run hosts regions of just one size. In other words,
a small run is associated with exactly one region size class.

That means that you can think of a small run as an array of regions:

|----------|
| region 0 |
|----------|
| region 1 |
|----------|
| ...      |
|----------|
| region N |
|----------|

You can view the layout of a small run by using the "jerun" command:

    (gdb) jerun -m 0x715ee37000
          status    address         preview             map
    ---------------------------------------------------------------------------
    0     used      0x715ee37000    000000715f9b2620    0xe0 region
    1     used      0x715ee370c0    000000715f7ef418    0x1400 region
    2     used      0x715ee37180    000000715f9b2620    0xe0 region
    3     used      0x715ee37240    000000717b74f8d8    libskia.so + 0x5528d8
    ...

You can also get a list of all the small runs of a specific size class
with the "jeregions" command:

    (gdb) jeregions 512
          run_addr        reg_size    run_size    usage
    -------------------------------------------------------
    1     0x715da0e000    512         0x1000      8/8
    2     0x715da0f000    512         0x1000      8/8
    3     0x715ef0b000    512         0x1000      8/8
    4     0x715ef0c000    512         0x1000      8/8

Finally, if you want to match an address to a region/run/chunk you can
use the "jeinfo" command:

    (gdb) jeinfo 0x715ee37000
    parent    address         size
    --------------------------------------
    arena     0x717a402200    -
    chunk     0x715ee00000    0x200000
    run       0x715ee37000    0x3000
    region    0x715ee37000    0xc0

# Memory Management Structures

XXX

## Backend

XXX

## Frontend

XXX

