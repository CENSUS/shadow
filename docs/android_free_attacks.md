In this file we use shadow to demonstrate how double, unaligned and
arbitrary free() bugs behave on Android's jemalloc.

You can find more information in our Infiltrate 2017 talk's slides
at: <https://census-labs.com/media/shadow-infiltrate-2017.pdf>

# Double-free

View the tcache bin stack for bin index 2.

    (gdb) jetcache -b 2
    index    lg_fill_div    ncached    low_water    ncached_max
    ---------------------------------------------------------------
    2        1              3          0x2          8

    stack
    ----------------
    0x7160571180
    0x715efa55a0
    0x715efa55c0

Bin index 2 corresponds to sizes 0x11-0x20.

    (gdb) jebininfo
    index    region_size    run_size    no_regions
    --------------------------------------------------
    0        0x8            0x1000      512
    1        0x10           0x1000      256
    2        0x20           0x1000      128
    3        0x30           0x3000      256
    ...

free() the same address twice using gdb.

    (gdb) jeinfo 0x715efa5580
    parent    address         size
    --------------------------------------
    arena     0x717a402200    -
    chunk     0x715ee00000    0x200000
    run       0x715efa5000    0x1000
    region    0x715efa5580    0x20

    (gdb) p free(0x715efa5580)
    $4 = 32
    (gdb) p free(0x715efa5580)
    $5 = 32

Parse the heap again and view the tcache bin stack.

    (gdb) jeparse
    [shadow] parsing structures from memory...
    [shadow] structures parsed

    (gdb) jetcache -b 2
    index    lg_fill_div    ncached    low_water    ncached_max
    ---------------------------------------------------------------
    2        1              5          0x2          8

    stack
    ----------------
    0x715efa5580
    0x715efa5580
    0x7160571180
    0x715efa55a0
    0x715efa55c0

The freed address was pushed in the tcache bin stack twice.

This means that the next two malloc() requests will return the same address.

You can actually push the same address into the stack multiple times, up until
the stack is full:

    (gdb) p free(0x715efa5580)
    $7 = 32

    (gdb) jeparse
    [shadow] parsing structures from memory...
    [shadow] structures parsed

    (gdb) jetcache -b 2
    index    lg_fill_div    ncached    low_water    ncached_max
    ---------------------------------------------------------------
    2        1              6          0x2          8

    stack
    ----------------
    0x715efa5580
    0x715efa5580
    0x715efa5580
    0x7160571180
    0x715efa55a0
    0x715efa55c0

    # ignore the fact that gdb can't properly print the address
    (gdb) printf "%p\n", malloc(0x20)
    0x5efa5580
    (gdb) printf "%p\n", malloc(0x20)
    0x5efa5580
    (gdb) printf "%p\n", malloc(0x20)
    0x5efa5580

# Unaligned Free

XXX

# Arbitrary Free

XXX

Search for addresses of libart.so that can be passed to free() and that
they'll be added to tcache bin index 0.

    (gdb) jefreecheck -b 0 libart.so

    [shadow] searching libart.so (0x7179bfa000 - 0x717a1ea000)
    [shadow] 0x7179fb5000
    [shadow] 0x717a02e000
    [shadow] 0x717a07d000
    [shadow] 0x717a0fe000
    [shadow] 0x717a17a000
    [shadow] 0x717a19f000
    [shadow] 0x717a1a1000
    [shadow] 0x717a1a3000
    [shadow] searching libart.so (0x717a1eb000 - 0x717a1fa000)
    [shadow] searching libart.so (0x717a1fa000 - 0x717a1fd000)

    (gdb) p free(0x7179fb5000)
    $2 = 8

    (gdb) jeparse
    [shadow] parsing structures from memory...
    [shadow] structures parsed

    (gdb) jetcache -b 0
    index    lg_fill_div    ncached    low_water    ncached_max
    ---------------------------------------------------------------
    0        1              6          0x1          8

    stack
    ----------------
    0x7179fb5000
    0x715f9e9940
    0x715f9e98f0
    0x715f9e9950
    0x715f9e9948
    0x715f9e9978

    (gdb) jeinfo 0x7179fb5000
    [shadow] Info about 0x7179fb5000
    module       offset
    -------------------------
    libart.so    0x3bb000

    # ignore the fact that gdb can't properly print the address
    (gdb) printf "%p\n", malloc(0x8)
    0x79fb5000

