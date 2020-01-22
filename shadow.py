# shadow - De Mysteriis Dom jemalloc

import os
import sys
import shutil
import time
import datetime
import copy
import tempfile

try:
    import ConfigParser
except:
    import configparser as ConfigParser

sys.path.append('.')

import jemalloc
import nursery
import symbol

VERSION = 'v2.0'

# globals
jeheap = None
arenas_addr = []
dbg_engine = None

# firefox globals
xul_version = ''
xul_symbols_pickle = ''
nursery_heap = nursery.nursery()

# android globals
android_version = ''


# detect debugger engine
try:
    import gdb
    import gdb_engine as dbg
    dbg_engine = 'gdb'
    storage_path = '/tmp/shadow'
    android_version = '8'
except ImportError:
    try:
        import pykd
        import pykd_engine as dbg
        if pykd.isWindbgExt():
            dbg_engine = 'pykd'
            storage_path = '%s\\shadow' % tempfile.gettempdir()

            xul_version = dbg.get_xul_version()

            if dbg.get_arch() == 'x86':
                xul_symbols_pickle = '%s\\pdb\\xul-%s.pdb.pkl' \
                        % (os.path.dirname(os.path.abspath(__file__)), xul_version)
            else:
                xul_symbols_pickle = '%s\\pdb\\xul-%s-x64.pdb.pkl' \
                        % (os.path.dirname(os.path.abspath(__file__)), xul_version)
    except ImportError:
        try:
            import lldb
            import lldb_engine as dbg
            dbg_engine = 'lldb'
            storage_path = '/tmp/shadow'
            android_version = '8'
        except ImportError:
            pass


def store_jeheap(path):
    try:
        import pyrsistence
    except ImportError:
        raise Exception("pyrsistence is needed for heap snapshots")

    global jeheap

    if not os.path.isdir(path):
        os.makedirs(path)

    chunks_p = "%s/chunks" % path
    runs_p = "%s/runs" % path
    arenas_p = "%s/arenas" % path
    tcaches_p = "%s/tcaches" % path
    bin_info_p = "%s/bin_info" % path
    modules_dict_p = "%s/modules_dict" % path
    jeheap_txt_p = "%s/jeheap.txt" % path

    # delete previous files
    if os.path.isfile(chunks_p):
        os.remove(chunks_p)
    if os.path.isfile(runs_p):
        os.remove(runs_p)
    if os.path.isfile(arenas_p):
        os.remove(arenas_p)
    if os.path.isfile(tcaches_p):
        os.remove(tcaches_p)
    if os.path.isfile(bin_info_p):
        os.remove(bin_info_p)
    if os.path.isfile(modules_dict_p):
        os.remove(modules_dict_p)
        if os.path.isfile(jeheap_txt_p):
            os.remove(jeheap_txt_p)

    # store
    chunks = pyrsistence.EMList(chunks_p)
    for chunk in jeheap.chunks:
        chunks.append(chunk)
    chunks.close()

    runs = pyrsistence.EMDict(runs_p)
    for k,v in jeheap.runs.items():
        runs[k] = v
    runs.close()

    arenas = pyrsistence.EMList(arenas_p)
    for arena in jeheap.arenas:
        arenas.append(arena)
    arenas.close()

    tcaches = pyrsistence.EMList(tcaches_p)
    for tcache in jeheap.tcaches:
        tcaches.append(tcache)
    tcaches.close()

    bin_info = pyrsistence.EMList(bin_info_p)
    for info in jeheap.bin_info:
        bin_info.append(info)
    bin_info.close()

    modules_dict = pyrsistence.EMDict(modules_dict_p)
    for k,v in jeheap.modules_dict.items():
        modules_dict[k] = v
    modules_dict.close()

    config = ConfigParser.RawConfigParser()
    config.add_section("jeheap")
    config.set("jeheap", "standalone", str(jeheap.standalone))
    config.set("jeheap", "dword_size", hex(jeheap.dword_size))
    config.set("jeheap", "narenas", hex(jeheap.narenas))
    config.set("jeheap", "nbins", hex(jeheap.nbins))
    config.set("jeheap", "chunk_size", hex(jeheap.chunk_size))

    with open(jeheap_txt_p, "w") as f:
        config.write(f)


def load_jeheap(path):
    return jemalloc.jemalloc(path=path)


def int_from_sym(symbols_list):
    for symbol in symbols_list:
        try:
            return dbg.to_int(dbg.get_value(symbol))
        except:
            continue
    return None


def is_standalone_variant():
    try:
        _ = dbg.addressof('je_arena_bin_info')
        return True
    except:
        return False


def has_symbols():
    try:
        _ = dbg.sizeof('arena_bin_info_t')
        return True
    except:
        return False


debug_log_f = None
debug_log = lambda x: None
def _debug_log(s):
    debug_log_f.write(s + "\n")


# parse functions
def parse(read_content_preview, config_path, do_debug_log=False):
    global jeheap
    global debug_log
    global debug_log_f
    global storage_path
    global android_version

    if do_debug_log:
        debug_log_p = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "debug.log")
        debug_log_f = open(debug_log_p, "w")
        debug_log = _debug_log
    else:
        debug_log = lambda x: None

    if config_path:
        print('[shadow] parsing configuration...')
        if 'android8' in config_path:
            android_version = '8'
        elif 'android7' in config_path:
            android_version = '7'
        elif 'android6' in config_path:
            android_version = '6'
        update_dbg_cache_from_config(config_path)
    else:
        if is_standalone_variant() and not has_symbols():
            print("[shadow] Detecting Android version...")
            chunksize = int_from_sym(["je_chunksize", "chunksize"])
            map_misc_offset = int_from_sym(["je_map_misc_offset"])

            shadow_path = os.path.dirname(os.path.realpath(__file__))
            cfg_path = os.path.join(shadow_path, "cfg")

            # android 7/8 32bit
            if chunksize == 0x80000:
                # android 8 32 bit
                if map_misc_offset == 0x230:
                    android_version = '8'
                    cfg_path = os.path.join(cfg_path, "android8_32.cfg")
                    print("[shadow] Using Android 8 32 bit configuration.")
                    print("         (%s)" % cfg_path)
                # android 8 64 bit
                elif map_misc_offset == 0x228:
                    android_version = '7'
                    cfg_path = os.path.join(cfg_path, "android7_32.cfg")
                    print("[shadow] Using Android 7 32 bit configuration.")
                    print("         (%s)" % cfg_path)
            # android 7/8 64bit
            elif chunksize == 0x200000:
                # android 8 64bit
                if map_misc_offset == 0x1010:
                    android_version = '8'
                    cfg_path = os.path.join(cfg_path, "android8_64.cfg")
                    print("[shadow] Using Android 8 64 bit configuration.")
                    print("         (%s)" % cfg_path)
                # android 7 64bit
                elif map_misc_offset == 0x1008:
                    android_version = '7'
                    cfg_path = os.path.join(cfg_path, "android7_64.cfg")
                    print("[shadow] Using Android 7 64 bit configuration.")
                    print("         (%s)" % cfg_path)
            # android 6 32bit
            elif chunksize == 0x40000 and dbg.get_dword_size() == 4:
                android_version = '6'
                cfg_path = os.path.join(cfg_path, "android6_32.cfg")
                print("[shadow] Using Android 6 32 bit configuration.")
                print("         (%s)" % cfg_path)
            # android 6 64bit
            elif chunksize == 0x40000 and dbg.get_dword_size() == 8:
                android_version = '6'
                cfg_path = os.path.join(cfg_path, "android6_64.cfg")
                print("[shadow] Using Android 6 64 bit configuration.")
                print("         (%s)" % cfg_path)
            else:
                print("[shadow] Could not detect Android version, try to use"
                      " a configuration file.")
                return
            update_dbg_cache_from_config(cfg_path)

    print('[shadow] parsing structures from memory...')
    print_timestamp()

    jeheap = jemalloc.jemalloc()
    parse_general(jeheap)
    parse_chunks(jeheap)
    parse_all_runs(jeheap, read_content_preview)
    parse_arenas(jeheap)
    if jeheap.standalone:
        parse_tbin_info(jeheap)
        parse_tcaches(jeheap)

    if dbg_engine == "pykd":
        path = os.path.join(storage_path, "jeheap")
        shutil.rmtree(path, ignore_errors=True)
        store_jeheap(path)

    # write current config
    p = os.path.join(storage_path, 'shadow.cfg')
    if not os.path.isdir(storage_path):
        os.makedirs(storage_path)
    generate_config(p)

    print('[shadow] structures parsed')
    print_timestamp()

    if debug_log_f:
        debug_log_f.close()


def parse_general(jeheap):
    global arenas_addr

    debug_log("parse_general()")

    jeheap.standalone = is_standalone_variant()

    jeheap.dword_size = dbg.get_dword_size()

    arenas_arr_addr = int_from_sym(['arenas', 'je_arenas'])

    jeheap.narenas = int_from_sym(['narenas', 'narenas_total',
                                   'je_narenas_total'])

    arenas_addr = dbg.read_dwords(arenas_arr_addr, jeheap.narenas)

    if jeheap.standalone:
        jeheap.chunk_size = int_from_sym(['chunksize', 'je_chunksize'])
    # firefox
    else:
        jeheap.chunk_size = 1 << 20

    # number of bins
    # first attempt
    jeheap.nbins = int_from_sym(['nbins'])

    # second attempt
    if not jeheap.nbins:
        jeheap.ntbins = int_from_sym(['ntbins'])
        jeheap.nsbins = int_from_sym(['nsbins'])
        jeheap.nqbins = int_from_sym(['nqbins'])
        if jeheap.ntbins and jeheap.nsbins and jeheap.nqbins:
            jeheap.nbins = jeheap.ntbins + jeheap.nsbins + jeheap.nqbins

    # third attempt
    # if dbg_engine == 'gdb':
    #     try:
    #         jeheap.nbins = int(dbg.execute('p __mallinfo_nbins()').split()[2])
    #     except:
    #         # print("[shadow] Using hardcoded number of bins.")
    #         pass

    # fourth attempt - hardcoded values
    if not jeheap.nbins:
        # android
        if jeheap.standalone:
            # android 64 bit
            if jeheap.dword_size == 8:
                jeheap.nbins = 36
            # android 32 bit
            elif jeheap.dword_size == 4:
                jeheap.nbins = 39

        # firefox
        else:
            # linux
            if dbg_engine == 'gdb':
                # 32bit
                if jeheap.dword_size == 4:
                    jeheap.nbins = 36
                # 64 bit
                else:
                    jeheap.nbins = 35
            # windows
            elif dbg_engine == 'pykd':
                # 32bit
                if jeheap.dword_size == 4:
                    jeheap.nbins = 35
                # 64 bit
                else:
                    jeheap.nbins = 34
            elif dbg_engine == 'lldb':
                # 32bit
                if jeheap.dword_size == 4:
                    jeheap.nbins = 36
                # 64 bit
                else:
                    jeheap.nbins = 35

    # standalone: parse the global je_arena_bin_info array
    if jeheap.standalone:
        info_addr = int(str(dbg.addressof('je_arena_bin_info')).split()[0], 16)
        info_size = dbg.sizeof('arena_bin_info_t')
        info_struct = "arena_bin_info_t"

    # firefox: parse the bins of arena[0]
    else:
        info_addr = arenas_addr[0] + dbg.offsetof('arena_t', 'bins')
        info_size = dbg.sizeof('arena_bin_t')
        info_struct = "arena_bin_t"

    int_size = dbg.int_size()
    dword_size = dbg.get_dword_size()

    bin_info_mem = dbg.read_bytes(info_addr, jeheap.nbins * info_size)
    # split memory into buffers of info_struct
    bin_info_mem = [bin_info_mem[i:i+info_size]
                    for i in range(0, jeheap.nbins * info_size, info_size)]

    for buf in bin_info_mem:
        reg_size = dbg.read_struct_member(buf, info_struct,
                                          "reg_size", dword_size)

        run_size = dbg.read_struct_member(buf, info_struct,
                                          "run_size", dword_size)

        reg0_off = dbg.read_struct_member(buf, info_struct,
                                          "reg0_offset", int_size)

        nregs = dbg.read_struct_member(buf, info_struct,
                                       "nregs", int_size)

        jeheap.bin_info.append(jemalloc.bin_info(reg_size,
                                                 run_size,
                                                 reg0_off,
                                                 nregs))

    for name, range_list in dbg.modules_dict().items():
        jeheap.modules_dict[name] = range_list


def parse_arenas(jeheap):
    global arenas_addr

    for i in range(0, jeheap.narenas):
        new_arena_addr = arenas_addr[i]
        if new_arena_addr == 0:
            continue

        new_arena = parse_arena(new_arena_addr, i, jeheap.nbins)

        # Add arena to the list of arenas
        jeheap.arenas.append(new_arena)


def parse_arena(addr, index, nbins):
    new_arena = jemalloc.arena(addr, index, [], [], [])

    # Read the array of bins
    bin_size = dbg.sizeof('arena_bin_t')
    bins_addr = addr + dbg.offsetof('arena_t', 'bins')
    bins_mem = dbg.read_bytes(bins_addr, nbins * bin_size)
    bins_mem = [bins_mem[z:z+bin_size]
                    for z in range(0, nbins * bin_size, bin_size)]

    # Now parse each bin
    for j in range(0, nbins):
        bin_addr = bins_addr + bin_size * j
        buf = bins_mem[j]
        new_arena.bins.append(parse_arena_bin(bin_addr, j, buf))

    return new_arena


def parse_arena_bin(addr, index, data):
    dword_size = dbg.get_dword_size()
    runcur = dbg.read_struct_member(data, "arena_bin_t", "runcur", dword_size)

    # associate run address with run object
    if runcur == 0:
        run = None
    else:
        run = jeheap.runs[str(runcur)]

    return jemalloc.arena_bin(addr, index, run)


def parse_run(jeheap, hdr_addr, addr, run_hdr, run_size, binind, read_content_preview):
    if hdr_addr == 0 or run_size == 0:
        return None

    bin_invalid = 0xff

    # case1: large run
    if binind == bin_invalid:
        return jemalloc.run(hdr_addr, addr, run_size, binind, 0, 0, [])

    # case2: small run
    bin_info = jeheap.bin_info
    run_size = bin_info[binind].run_size
    region_size = bin_info[binind].reg_size
    reg0_offset = bin_info[binind].reg0_off
    total_regions = bin_info[binind].nregs

    free_regions = dbg.read_struct_member(run_hdr, "arena_run_t",
                                          "nfree", dbg.int_size())

    # run bitmap parsing
    regs_mask_bits = (total_regions // 8) + 1

    # "regs_mask" member changed to "bitmap" in the standalone version
    if jeheap.standalone:
        regs_mask_offset = dbg.offsetof('arena_run_t', 'bitmap')
    else:
        regs_mask_offset = dbg.offsetof('arena_run_t', 'regs_mask')

    regs_mask_bytearr = run_hdr[regs_mask_offset:
                                regs_mask_offset + regs_mask_bits]

    # parse the bitmap and store the bits to regs_mask
    regs_mask = []

    for byte in regs_mask_bytearr:
        for bit_pos in range(0, 8):
            if len(regs_mask) >= total_regions:
                break
            if byte & (1 << bit_pos) > 0:
                regs_mask.append(1)
            else:
                regs_mask.append(0)

    # regions parsing loop
    regions = []
    reg0_addr = addr + reg0_offset

    if read_content_preview:
        n_dwords = run_size // jeheap.dword_size
        run_mem = dbg.read_dwords(addr, n_dwords)

    for i in range(0, total_regions):
        reg_addr = reg0_addr + (i * region_size)

        data = None
        data_map = None
        if read_content_preview:
            idx = (reg_addr - addr) // jeheap.dword_size
            data = run_mem[idx]

        regions.append(jemalloc.region(i, reg_addr, region_size,
                                       regs_mask[i], data, data_map))

    return jemalloc.run(hdr_addr, addr, run_size, binind, free_regions,
                        regs_mask, regions)


# parse the metadata of all runs and their regions
def parse_all_runs(jeheap, read_content_preview):
    global dbg_engine

    debug_log("parse_all_runs()")
    # parse the bitmap of each chunk and find all the runs

    # the arena_run_t header in the standalone version is stored at a
    # map_misc array inside arena_chunk_t. The offset of this member can be
    # found through the je_map_misc_offset symbol
    if jeheap.standalone:
        bits_offset = dbg.offsetof('arena_chunk_map_bits_t', 'bits') // jeheap.dword_size
        chunk_map_dwords = dbg.sizeof('arena_chunk_map_bits_t') // jeheap.dword_size
        bitmap_off = dbg.offsetof('arena_chunk_t', 'map_bits')
        chunk_arena_off = dbg.offsetof('arena_chunk_t', 'node') \
                          + dbg.offsetof('extent_node_t', 'en_arena')
        map_misc_offset = dbg.to_int(dbg.get_value('je_map_misc_offset'))
        arena_run_bin_off = None
        map_bias = int_from_sym(['je_map_bias'])

    # the arena_run_t header is stored at the hdr_addr of each run in
    # the firefox version
    else:
        bits_offset = dbg.offsetof('arena_chunk_map_t', 'bits') // jeheap.dword_size
        chunk_map_dwords = dbg.sizeof('arena_chunk_map_t') // jeheap.dword_size
        bitmap_off = dbg.offsetof('arena_chunk_t', 'map')
        chunk_arena_off = dbg.offsetof('arena_chunk_t', 'arena')
        map_misc_offset = None
        arena_run_bin_off = dbg.offsetof('arena_run_t', 'bin')
        map_bias = 0

    arena_bin_size = dbg.sizeof('arena_bin_t')
    bins_offset = dbg.offsetof('arena_t', 'bins')

    chunk_npages = jeheap.chunk_size >> 12
    bitmap_len = (chunk_npages - map_bias) * chunk_map_dwords

    # the 12 least significant bits of each bitmap entry hold
    # various flags for the corresponding run
    flags_mask = (1 << 12) - 1

    dword_size = dbg.get_dword_size()

    for chunk in jeheap.chunks:
        debug_log("  parsing chunk @ 0x%x" % chunk.addr)

        # does this skip huge regions?
        if not chunk.arena_addr:
            debug_log("    no arena_addr, skpping")
            continue

        if jeheap.standalone:
            chunk_mem = dbg.read_bytes(chunk.addr, map_bias * dbg.get_page_size())
        else:
            chunk_mem = dbg.read_bytes(chunk.addr, jeheap.chunk_size)

        if jeheap.standalone:
            node_off = dbg.offsetof("arena_chunk_t", "node")
            en_addr_off = dbg.offsetof("extent_node_t", "en_addr")
            en_addr = dbg.dword_from_buf(chunk_mem, node_off + en_addr_off)

            if en_addr != chunk.addr:
                continue

        # read the chunk bitmap
        off = bitmap_off
        bitmap_dwords = []
        for i in range(bitmap_len):
            bitmap_dwords.append(dbg.dword_from_buf(chunk_mem, off))
            off += dword_size

        bitmap = [bitmap_dwords[i] for i in range(int(bits_offset), \
                                           int(len(bitmap_dwords)), int(bits_offset + 1))]

        # parse chunk bitmap elements
        i = -1
        for mapelm in bitmap:
            i += 1
            unallocated = False
            debug_log("    [%04d] mapelm = 0x%x" % (i, mapelm))

            # standalone version
            if jeheap.standalone:
                # small run
                if mapelm & 0xf == 1:
                    debug_log("      small run")

                    if android_version == '6':
                        offset = mapelm & ~flags_mask
                        binind = (mapelm & 0xFF0) >> 4
                    elif android_version == '7' or android_version == '8':
                        offset = (mapelm & ~0x1FFF) >> 1
                        binind = (mapelm & 0x1FE0) >> 5

                    debug_log("      offset = 0x%x" % offset)

                    # part of the previous run
                    if offset != 0:
                        continue

                    debug_log("      binind = 0x%x" % binind)

                    size = jeheap.bin_info[binind].run_size
                    debug_log("      size = 0x%x" % size)

                # large run
                elif mapelm & 0xf == 3:
                    debug_log("      large run")

                    if android_version == '6':
                        size = mapelm & ~flags_mask
                    elif android_version == '7' or android_version == '8':
                        size = (mapelm & ~0x1FFF) >> 1

                    binind = 0xff
                    debug_log("      size = 0x%x" % size)

                # unallocated run
                else:
                    debug_log("      unallocated run")

                    if android_version == '6':
                        size = mapelm & ~flags_mask
                    elif android_version == '7' or android_version == '8':
                        size = (mapelm & ~0x1FFF) >> 1

                    unallocated = True
                    binind = 0xff
                    debug_log("      size = 0x%x" % size)

                map_misc_addr = chunk.addr + map_misc_offset

                cur_arena_chunk_map_misc = map_misc_addr + \
                                           i * dbg.sizeof('arena_chunk_map_misc_t')

                hdr_addr = cur_arena_chunk_map_misc + \
                           dbg.offsetof('arena_chunk_map_misc_t', 'run')

                debug_log("      run_hdr = 0x%x" % hdr_addr)

                run_hdr_off = map_misc_offset \
                              + i * dbg.sizeof('arena_chunk_map_misc_t') \
                              + dbg.offsetof('arena_chunk_map_misc_t', 'run')

                run_hdr = chunk_mem[run_hdr_off:
                                    run_hdr_off + dbg.sizeof("arena_run_t")]
                addr =  chunk.addr + (i + map_bias) * dbg.get_page_size()

            # Firefox
            else:
                # small run
                if mapelm & 0xf == 1:
                    hdr_addr = mapelm & ~flags_mask
                    off = hdr_addr - chunk.addr

                    # part of the previous run
                    if str(hdr_addr) in jeheap.runs:
                        continue

                    run_hdr = chunk_mem[off:off+dbg.sizeof("arena_run_t")]
                    bin_addr = dbg.dword_from_buf(run_hdr, arena_run_bin_off)

                    # firefox stores the bin addr, we can find the binind as follows:
                    binind = (bin_addr - (chunk.arena_addr + bins_offset)) // arena_bin_size

                    size = jeheap.bin_info[binind].run_size

                    run_hdr_sz = dbg.sizeof("arena_run_t")
                    run_hdr_sz += (jeheap.bin_info[binind].nregs // 8) + 1
                    run_hdr = chunk_mem[off:
                                        off + run_hdr_sz]

                # large run
                elif mapelm & 0xf == 3:
                    hdr_addr = chunk.addr + i * dbg.get_page_size()
                    off = hdr_addr - chunk.addr
                    run_hdr = chunk_mem[off:
                                        off + dbg.sizeof("arena_run_t")]

                    size = mapelm & ~flags_mask
                    binind = 0xff

                # unallocated run
                else:
                    debug_log("      unallocated page")
                    continue

                addr = hdr_addr

            if hdr_addr == 0 or size == 0:
                debug_log("      hdr_addr or size is 0, skipping")
                continue
            debug_log("      addr = 0x%x" % addr)

            new_run = parse_run(jeheap, hdr_addr, addr, run_hdr, size, binind,
                                read_content_preview)
            new_run.unallocated = unallocated
            jeheap.runs[str(hdr_addr)] = new_run

            chunk.runs.append(hdr_addr)


# parse all jemalloc chunks
def parse_chunks(jeheap):
    debug_log("parse_chunks()")

    dword_size = dbg.get_dword_size()

    if jeheap.standalone:
        chunks_rtree_addr = int(str(dbg.addressof('je_chunks_rtree')).split()[0], 16)
        rtree_mem = dbg.read_bytes(chunks_rtree_addr, dbg.sizeof("rtree_t"))

        max_height = dbg.read_struct_member(rtree_mem, "rtree_t",
                                            "height", dbg.int_size())

        # levels[] is of type rtree_level_t
        levels_arr_addr = chunks_rtree_addr + \
                           dbg.offsetof('rtree_t', 'levels')

        rtree_level_size = dbg.sizeof('rtree_level_t')

        rtree_levels_mem = dbg.read_bytes(levels_arr_addr,
                                          rtree_level_size * max_height)

        root = None
        for height in range(0, max_height):
            off = height * rtree_level_size
            level_mem = rtree_levels_mem[off:off+rtree_level_size]
            addr = dbg.read_struct_member(level_mem, "rtree_level_t",
                                          "subtree", dword_size)

            if addr == 0:
                continue

            root = (addr, height)
            break

    # firefox
    else:
        chunks_rtree_addr = int_from_sym(['chunk_rtree'])
        rtree_mem = dbg.read_bytes(chunks_rtree_addr, dbg.sizeof("malloc_rtree_t"))

        max_height = dbg.read_struct_member(rtree_mem, "malloc_rtree_t",
                                            "height", dbg.int_size())

        root = dbg.read_struct_member(rtree_mem, "malloc_rtree_t",
                                      "root", dbg.get_dword_size())
        root = (root, 0)

        levels_arr_addr = chunks_rtree_addr + \
                           dbg.offsetof('malloc_rtree_t', 'level2bits')

        rtree_level_size = dbg.int_size()

        rtree_levels_mem = dbg.read_bytes(levels_arr_addr,
                                          rtree_level_size * max_height)


        off = 0
        level2bits = []
        for i in range(0, max_height):
            level2bits.append(dbg.int_from_buf(rtree_levels_mem, off))
            off += dbg.int_size()

    if not root:
        raise Exception("[shadow] Could not find the root of chunks_rtree.")

    stack = []
    stack.append(root)
    while len(stack):
        (node, height) = stack.pop()

        if jeheap.standalone:
            cur_level_addr = levels_arr_addr + height * rtree_level_size
            bits = dbg.read_memory(cur_level_addr +
                                   dbg.offsetof('rtree_level_t', 'bits'),
                                   dbg.int_size())
        else:
            bits = level2bits[height]

        max_key = 1 << bits
        subtree = dbg.read_dwords(node, max_key)

        for addr in subtree:
            if addr == 0:
                continue


            if height == max_height - 1:
                if jeheap.standalone:
                    node_addr = addr + dbg.offsetof('arena_chunk_t', 'node')

                    en_arena = dbg.read_dword(node_addr +
                                              dbg.offsetof('extent_node_t', 'en_arena'))
                    arena_addr = en_arena

                else:
                    try:
                        arena_addr = dbg.read_dword(addr +
                                                    dbg.offsetof('arena_chunk_t', 'arena'))
                    except:
                        arena_addr = 0

                global arenas_addr
                exists = False
                if arena_addr in arenas_addr:
                    exists = True

                # this fixes the weird case where a non page aligned
                # chunk address is found, for example:
                # ...
                # chunk @ 0xcc4ef4c0  <-- actually belongs to chunk 0xcc480000
                # chunk @ 0xcc280000                                     |
                # chunk @ 0xcc480000  <----------------------------------|
                # ...
                # XXX: investigate this
                if addr & 0xfff:
                    debug_log("  skipping non-page aligned chunk address 0x%x" % addr)
                    continue

                if exists:
                    debug_log("  chunk @ 0x%x" % addr)
                    jeheap.chunks.append(
                        jemalloc.chunk(addr, arena_addr, []))
                else:
                    debug_log("  non-arena chunk @ 0x%x" % addr)
                    jeheap.chunks.append(
                        jemalloc.chunk(addr, None, []))
            else:
                stack.append((addr, height + 1))



# config functions
def update_dbg_cache_from_config(config_path):
    config = ConfigParser.RawConfigParser()
    config.read(config_path)

    if config.has_section('offsets'):
        for name,value in config.items('offsets'):
            dbg.cache_offsets[name] = int(value, 16)

    if config.has_section('values'):
        for name,value in config.items('values'):
            dbg.cache_values[name] = int(value, 16)

    if config.has_section('sizes'):
        for name,value in config.items('sizes'):
            dbg.cache_sizes[name] = int(value, 16)


def generate_config(config_path):
    config = ConfigParser.RawConfigParser()
    config.add_section('values')
    for name,value in dbg.cache_values.items():
        if str(value).startswith('0x'):
            config.set('values', name, str(value))
        else:
            config.set('values', name, hex(int(value)))

    config.add_section('offsets')
    for name,value in dbg.cache_offsets.items():
        config.set('offsets', name, hex(value))

    config.add_section('sizes')
    for name,value in dbg.cache_sizes.items():
        config.set('sizes', name, hex(value))

    with open(config_path, 'w') as f:
        config.write(f)


def parse_tbin_info(jeheap):
    nhbins = int_from_sym(['je_nhbins', 'nhbins'])
    int_size = dbg.int_size()
    addr = dbg.get_value('je_tcache_bin_info')
    size = nhbins * int_size
    mem = dbg.read_bytes(addr, size)

    off = 0
    while off < len(mem):
        ncached_max = dbg.int_from_buf(mem, off)
        off += int_size
        jeheap.tbin_info.append(jemalloc.tbin_info(ncached_max))


def parse_tcaches(jeheap):
    nhbins = int_from_sym(['je_nhbins', 'nhbins'])
    dword_size = dbg.get_dword_size()

    max_cached = 0
    for tbinfo in jeheap.tbin_info:
        max_cached += tbinfo.ncached_max

    tcache_size = dbg.offsetof("tcache_t", "tbins") + \
                  (dbg.sizeof("tcache_bin_t") * nhbins) + \
                  (max_cached * dword_size)
    tcache_size = size2bin_size(jeheap, tcache_size)


    # tcache_size = 0x1C00
    BIONIC_PTHREAD_KEY_COUNT = 141
    arenas_addr = [arena.addr for arena in jeheap.arenas]
    data_off = dbg.offsetof("pthread_key_data_t" , "data")
    pthread_internal_size = dbg.sizeof("pthread_internal_t")
    key_data_off = dbg.offsetof('pthread_internal_t', 'key_data')
    key_data_size = dbg.sizeof('pthread_key_data_t') * BIONIC_PTHREAD_KEY_COUNT

    # g_thread_list points to the first pthread_internal_t struct
    elm_addr = dbg.get_value("g_thread_list", True)
    while elm_addr != 0:
        elm_mem = dbg.read_bytes(elm_addr, pthread_internal_size)
        elm_tid = dbg.read_struct_member(elm_mem, "pthread_internal_t",
                                         "tid", dbg.int_size())


        # key_data array
        key_data = elm_mem[key_data_off:key_data_off + key_data_size]

        # transform to a list containing only the key_data->data
        off = data_off
        key_data_data = []
        while off < len(key_data):
            data = dbg.dword_from_buf(key_data, off)
            key_data_data.append(data)
            off += data_off

        # search for jemalloc TSD(Thread Specific Data)
        tsd_addr = 0
        for data in key_data_data:
            if data == 0:
                continue
            # check if data is a ptr
            addr = data
            addr_info = find_address(addr, jeheap)
            # jemalloc TSD is a 0x80 region that contains pointers to the
            # tcache and the arena; unsure if we can rely on their offsets
            # so we parse the region's data to make sure

            if addr_info.region:
                region_dwords = dbg.read_dwords(addr_info.region.addr,
                                                addr_info.region.size)

                for dword in region_dwords:
                    if dword in arenas_addr:
                        tsd_addr, tsd_dwords = addr, region_dwords
                        break
                if tsd_addr:
                    break

        if not tsd_addr:
            k = str(elm_tid)
            jeheap.tcaches[k] = None
            elm_addr = dbg.read_struct_member(elm_mem, "pthread_internal_t",
                                              "next", dbg.get_dword_size())
            continue

        arena_addr = 0
        tcache_addr = 0
        for dword in tsd_dwords:
            if arena_addr and tcache_addr:
                break
            if dword in arenas_addr:
                arena_addr = dword
                continue
            addr_info = find_address(dword, jeheap)
            if addr_info.region:
                if addr_info.region.size == tcache_size:
                    tcache_addr = dword
                    continue

        if not arena_addr:
            # print("[shadow] Could not find the arena for thread %d" % elm_tid)
            k = str(elm_tid)
            jeheap.tcaches[k] = None
            elm_addr = dbg.read_struct_member(elm_mem, "pthread_internal_t",
                                              "next", dbg.get_dword_size())
            continue

        if not tcache_addr:
            # print("[shadow] Could not find the tcache for thread %d" % elm_tid)
            k = str(elm_tid)
            jeheap.tcaches[k] = None
            elm_addr = dbg.read_struct_member(elm_mem, "pthread_internal_t",
                                              "next", dbg.get_dword_size())
            continue


        # add to jeheap tcaches dict
        k = str(elm_tid)
        tcache_mem = dbg.read_bytes(tcache_addr, tcache_size)
        jeheap.tcaches[k] = parse_tcache(tcache_addr, tcache_mem, elm_tid)

        # match tid with arena
        for arena in jeheap.arenas:
            if arena_addr == arena.addr:
                arena.tids.append(elm_tid)

        # next
        elm_addr = dbg.read_struct_member(elm_mem, "pthread_internal_t",
                                          "next", dbg.get_dword_size())



def parse_tcache(addr, mem, tid):
    dword_size = dbg.get_dword_size()
    int_size = dbg.int_size()
    tbins_off = dbg.offsetof("tcache_t", "tbins")
    tbin_size = dbg.sizeof("tcache_bin_t")
    avail_off = dbg.offsetof("tcache_bin_t", "avail")

    tbins = []
    tbins_mem = mem[tbins_off:]

    off = 0
    for i in range(0, jeheap.nbins):
        tbin_mem = tbins_mem[off:off+tbin_size]

        tbin_addr = addr + tbins_off + off

        avail = dbg.read_struct_member(tbin_mem, "tcache_bin_t",
                                       "avail", dword_size)
        ncached = dbg.read_struct_member(tbin_mem, "tcache_bin_t",
                                         "ncached", int_size)
        lg_fill_div = dbg.read_struct_member(tbin_mem, "tcache_bin_t",
                                             "lg_fill_div", int_size)
        low_water = dbg.read_struct_member(tbin_mem, "tcache_bin_t",
                                             "low_water", int_size)

        ncached_max = jeheap.tbin_info[i].ncached_max

        stack_size = ncached_max * dword_size

        if android_version == '7' or android_version == '8':
            avail_off = avail - addr - (ncached_max * dword_size)
            stack_mem = mem[avail_off:avail_off+stack_size]
            stack = []
            cur_addr_off = 0
            while cur_addr_off < len(stack_mem):
                region_addr = dbg.dword_from_buf(stack_mem, cur_addr_off)
                stack.append(region_addr)
                cur_addr_off += dword_size

            stack = stack[ncached_max - ncached:]
            tbins.append(jemalloc.tcache_bin(tbin_addr, i, low_water, lg_fill_div,
                                             ncached, avail, stack))
            off += tbin_size

        elif android_version == '6':
            avail_off = avail - addr
            stack_mem = mem[avail_off:avail_off+stack_size]
            stack = []
            cur_addr_off = 0
            while cur_addr_off < len(stack_mem):
                region_addr = dbg.dword_from_buf(stack_mem, cur_addr_off)
                stack.append(region_addr)
                cur_addr_off += dword_size

            stack = stack[::-1]
            stack = stack[ncached_max - ncached:]
            tbins.append(jemalloc.tcache_bin(tbin_addr, i, low_water, lg_fill_div,
                                             ncached, avail, stack))
            off += tbin_size


    return jemalloc.tcache(addr, tid, tbins)


def jefreecheck_search(ptr):
    lg_page = 12
    map_bias = int_from_sym(['je_map_bias'])
    chunk_size = int_from_sym(['chunksize', 'je_chunksize'])
    chunk_npages = chunk_size >> lg_page

    def addr2base(ptr):
        return ptr & ~(chunk_size - 1)

    def pageind(ptr):
        return (ptr - addr2base(ptr)) >> lg_page

    if pageind(ptr) < map_bias:
        # print('[shadow] map_bias fail')
        return -1

    if pageind(ptr) >= chunk_npages:
        # print('[shadow] chunk_npages fail')
        return -1

    mapbits_addr = addr2base(ptr) + dbg.offsetof('arena_chunk_t', 'map_bits')
    mapbits_addr += (pageind(ptr) - map_bias) * 8
    try:
        mapbits = dbg.read_dword(mapbits_addr)
    except:
        return -1
    # print('[shadow] fake mapbits = 0x%x' % mapbits)

    if mapbits & 1 == 0:
        # print('[shadow] mapbits fail')
        return -1

    if mapbits & 2 != 0:
        # print('[shadow] mapbits large alloc bit is set')
        return -1

    # print('[shadow] mapbits success')
    if android_version == '6':
        binind = (mapbits & 0xFF0) >> 4
    elif android_version == '7' or android_version == '8':
        binind = (mapbits & 0x1FE0) >> 5

    # print('[shadow] fake binind = 0x%x' % binind)
    return binind


def jefreecheck(tbin_index, objfile_search):
    page_size = 0x1000

    for ln in dbg.execute('info proc mappings').split('\n'):
        # [start, end, size, offset, objfile]
        l = ln.split()
        # skip if objfile is missing
        if len(l) < 5:
            continue
        # skip the first line
        if l[0] == 'Start':
            continue
        #todo: filter out [stack], [vsyscall], etc?
        objfile = l[4]

        if objfile_search is not None:
            if objfile_search not in objfile:
                continue

        objfile = objfile.split("/")[-1]
        start = int(l[0], 16)
        end = int(l[1], 16)

        print('[shadow] searching %s (0x%x - 0x%x)' % (objfile, start, end))
        for ptr in range(start, end, page_size):
            binind = jefreecheck_search(ptr)
            if binind == -1:
                continue

            if tbin_index is not None:
                if binind == tbin_index:
                    print('[shadow] 0x%x' % ptr)
            else:
                print('[shadow] 0x%x, index = 0x%x(%d)' % (ptr, binind, binind))

def help():
    '''Details about the commands provided by shadow'''

    print('\n[shadow] De Mysteriis Dom jemalloc')
    print('[shadow] shadow %s' % (VERSION))

    if is_standalone_variant():
        print('[shadow] Android v%s (%s)\n' % (android_version, dbg.get_arch()))
    else:
        print('[shadow] Firefox v%s (%s)\n' % (xul_version, dbg.get_arch()))

    print('[shadow] jemalloc-specific commands:')
    print('[shadow]   jechunks                : dump info on all available chunks')
    print('[shadow]   jearenas                : dump info on jemalloc arenas')
    print('[shadow]   jerun [-m] <address>    : dump info on a single run')
    print('[shadow]                                 -m : map content preview to metadata')
    print('[shadow]   jeruns [-cs]            : dump info on jemalloc runs')
    print('[shadow]                                 -c : current runs only')
    print('[shadow]                    -s <size class> : runs for the given size class only')
    print('[shadow]   jebins                  : dump info on jemalloc bins')
    print('[shadow]   jebininfo               : dump info on bin sizes ')
    print('[shadow]   jesize2bin              : convert size to bin index')
    print('[shadow]   jeregions <size class>  : dump all runs that host the regions of')
    print('[shadow]                             the given size class')
    print('[shadow]   jesearch [-cs] <hex>    : search the heap for the given hex dword')
    print('[shadow]                                 -c : current runs only')
    print('[shadow]                    -s <size class> : regions of the given size only')
    print('[shadow]   jeinfo <address>        : display all available details for an address')
    print('[shadow]   jedump [path]           : store the heap snapshot to the current')
    print('[shadow]                             working directory or to the specified path')
    print('[shadow]   jestore [path]          : jedump alias')
    print('[shadow]   jetcaches               : dump info on all tcaches')
    print('[shadow]   jetcache [-bs] <tid>    : dump info on single tcache')
    print('[shadow]                    -b <bin index>  : info for the given bin index only')
    print('[shadow]                    -s <size class> : info for the given size class only')
    print('[shadow]   jeparse [-crv]           : parse jemalloc structures from memory')
    print('[shadow]                   -c <config file> : jemalloc target config file')
    print('[shadow]                                 -r : read content preview')
    print('[shadow]                                 -v : produce debug.log')
    print('[shadow] Firefox-specific (pykd only) commands:')
    print('[shadow]   nursery                 : display info on the SpiderMonkey GC nursery')
    print('[shadow]   symbol [-vjdx] <size>   : display all Firefox symbols of the given size')
    print('[shadow]                                 -v : only class symbols with vtable')
    print('[shadow]                                 -j : only symbols from SpiderMonkey')
    print('[shadow]                                 -d : only DOM symbols')
    print('[shadow]                                 -x : only non-SpiderMonkey symbols')
    print('[shadow]   pa <address> [<length>] : modify the ArrayObject\'s length (default new length 0x666)')
    print('[shadow] Android-specific commands:')
    print('[shadow]   jefreecheck [-bm]                : display addresses that can be passed to free()')
    print('[shadow]                     -b <bin index> : display addresses that will be freed to')
    print('[shadow]                                      the tcache bin of <bin index>')
    print('[shadow]                          -m <name> : only search this specific module')
    print('[shadow] Generic commands:')
    print('[shadow]   jeversion               : output version number')
    print('[shadow]   jehelp                  : this help message')



def print_timestamp():
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    print('[shadow] %s' % (st))


def version():
    '''Output version number'''

    global VERSION
    print('[shadow] shadow %s' % (VERSION))


def firefox_version():
    '''Output Firefox's version we are attached to'''

    global xul_version
    print('[shadow] Firefox v%s (%s)' % (xul_version, dbg.get_arch()))



def size2bin_size(jeheap, size):
    max_small_size = jeheap.bin_info[jeheap.nbins - 1].reg_size
    if size > max_small_size:
        return None

    for i in range(1, jeheap.nbins):
        if jeheap.bin_info[i-1].reg_size <= size < jeheap.bin_info[i].reg_size:
            return jeheap.bin_info[i].reg_size


def size2binind(jeheap, size):
    i = 0
    binind = None
    prev_size = 0
    for info in jeheap.bin_info:
        if prev_size < size <= info.reg_size:
            binind = i
            break
        i += 1
        prev_size = info.reg_size

    return binind


def print_size2binind(size):
    global jeheap

    if dbg_engine == "pykd":
        path = os.path.join(storage_path, "jeheap")
        jeheap = load_jeheap(path)

    if not jeheap:
        print("[shadow] Parsed heap object not found, use jeparse.")
        return

    binind = size2binind(jeheap, size)

    if binind is None:
        print("[shadow] Could not match size with a bin index.")
        return

    print("[shadow] Size 0x%x(%d) belongs to bin index %d." %
          (size, size, binind))


# dump functions
def dump_all(path=None):
    if not path:
        path = os.getcwd()

    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y%m%d_%H%M%S')
    st = 'jeheap_' + st
    path = os.path.join(path, st)

    store_jeheap(path)
    print('[shadow] Heap snapshot saved at %s' % path)


def dump_bin_info():
    global jeheap

    if dbg_engine == "pykd":
        path = os.path.join(storage_path, "jeheap")
        jeheap = load_jeheap(path)

    if not jeheap:
        print("[shadow] Parsed heap object not found, use jeparse.")
        return

    i = 0
    table = [("index", "region_size", "run_size", "no_regions")]
    for info in jeheap.bin_info:
        table.append((i , hex(info.reg_size),
                      hex(info.run_size), info.nregs))
        i += 1
    print(ascii_table(table))


def dump_chunks():
    global jeheap

    if dbg_engine == "pykd":
        path = os.path.join(storage_path, "jeheap")
        jeheap = load_jeheap(path)

    if not jeheap:
        print("[shadow] Parsed heap object not found, use jeparse.")
        return

    table = [("addr", "arena", "no_runs")]
    for chunk in jeheap.chunks:
        try:
            chunk_arena_addr = hex(chunk.arena_addr)
        except:
            chunk_arena_addr = 'None'

        table.append((hex(chunk.addr), chunk_arena_addr, len(chunk.runs)))

    print(ascii_table(table))


def dump_chunk(addr):
    global jeheap

    if dbg_engine == "pykd":
        path = os.path.join(storage_path, "jeheap")
        jeheap = load_jeheap(path)

    if not jeheap:
        print("[shadow] Parsed heap object not found, use jeparse.")
        return


    chunk = None
    # 1. check if addr is the start of a chunk
    for cur_chunk in jeheap.chunks:
        if cur_chunk.addr == addr:
            chunk = cur_chunk
            break

    # 2. check if addr belongs to a chunk
    if not chunk:
        addr_info = find_address(addr, jeheap)
        chunk = addr_info.chunk

    if not chunk:
        print("[shadow] Address 0x%x does not belong to a chunk." % addr)
        return

    table = [("addr", "info", "size", "usage")]

    if jeheap.standalone:
        map_bias = int_from_sym(['je_map_bias'])
        table.append((hex(chunk.addr), "headers",
                      hex(map_bias << 12), "-"))

    for i in range(len(chunk.runs)):
        run_addr = chunk.runs[i]
        run = jeheap.runs[str(run_addr)]

        # check for unused gaps
        start = run.addr
        size = run.size
        if i < len(chunk.runs) - 1:
            next_run = jeheap.runs[str(chunk.runs[i+1])]
            next = next_run.addr

        else:
            next = chunk.addr + jeheap.chunk_size

        if run.binind == 0xff:
            info = "large run"
            usage = "-"
        else:
            info = "small run (0x%x)" % jeheap.bin_info[run.binind].reg_size
            no_regions = len(run.regions)
            usage = "%d/%d" % (no_regions - run.nfree, no_regions)

        table.append((hex(run.addr), info,
                      hex(run.size), usage))

        # unused gap
        if start + size != next:
            table.append((hex(start + size), "unused range",
                          hex(next - start + size), "-"))

    print("This chunk belongs to the arena at 0x%x." % chunk.arena_addr)
    print("")
    print(ascii_table(table))


def dump_arenas():
    global jeheap

    if dbg_engine == "pykd":
        path = os.path.join(storage_path, "jeheap")
        jeheap = load_jeheap(path)

    if not jeheap:
        print("[shadow] Parsed heap object not found, use jeparse.")
        return

    if jeheap.standalone:
        table = [("index", "address", "bins", "chunks", "threads")]
        for i in range(0, len(jeheap.arenas)):
            arena = jeheap.arenas[i]
            no_chunks = 0
            for chunk in jeheap.chunks:
                if chunk.arena_addr == arena.addr:
                    no_chunks += 1

            # :(
            j = 0
            z = 0
            tids_str = [""]
            for tid in arena.tids:
                if j == len(arena.tids) - 1:
                    tids_str[z] += "%s" % tid
                else:
                    tids_str[z] += "%s, " % tid

                j += 1
                if j % 4 == 0:
                    tids_str.append("")
                    z += 1

            table.append((arena.index, hex(arena.addr),
                          len(arena.bins), no_chunks,
                          tids_str[0]))
            if len(tids_str) > 1:
                for x in range(1, len(tids_str)):
                    table.append(("","","","",tids_str[x]))

            table.append(("","","","", ""))

        print(ascii_table(table))

    # firefox
    else:
        table = [("index", "address", "bins", "chunks")]
        for i in range(0, len(jeheap.arenas)):
            arena = jeheap.arenas[i]
            no_chunks = 0
            for chunk in jeheap.chunks:
                if chunk.arena_addr == arena.addr:
                    no_chunks += 1
            table.append((arena.index, hex(arena.addr),
                          len(arena.bins), no_chunks))

        print(ascii_table(table))



def dump_runs(dump_current_runs=False, size_class=0):
    global jeheap

    if dbg_engine == "pykd":
        path = os.path.join(storage_path, "jeheap")
        jeheap = load_jeheap(path)

    if not jeheap:
        print("[shadow] Parsed heap object not found, use jeparse.")
        return

    if dump_current_runs:
        for i in range(0, len(jeheap.arenas)):
            print("* arena[%d]" % i)
            print("")
            table = [("region size", "run address", "run size", "usage", "allocated")]

            for j in range(0, len(jeheap.arenas[i].bins)):
                run = jeheap.arenas[i].bins[j].runcur
                if run is None:
                    run_addr = "-"
                    run_size = "-"
                    run_usage = "-"
                    run_alloc = "-"

                elif run.unallocated:
                    run_addr = hex(run.addr)
                    run_size = hex(jeheap.bin_info[j].run_size)
                    no_free = "-"
                    no_regions = "-"
                    run_usage = "-"
                    run_alloc = "false"

                else:
                    run_addr = hex(run.addr)
                    run_size = hex(jeheap.bin_info[j].run_size)
                    no_free = run.nfree
                    no_regions = jeheap.bin_info[j].nregs
                    run_usage = "%d/%d" % (no_regions - no_free, no_regions)
                    run_alloc = "true"

                reg_size = hex(jeheap.bin_info[j].reg_size)
                if size_class == 0 or size_class == jeheap.bin_info[j].reg_size:
                    table.append((reg_size,
                                  run_addr,
                                  run_size,
                                  run_usage,
                                  run_alloc))

            print(ascii_table(table))

    # all runs
    else:
        i = 0
        table = []
        for _,run in jeheap.runs.items():
            if run is None:
                continue

            i += 1
            if size_class == 0:
                # unallocated run
                if run.unallocated:
                    table.append([i,
                                  hex(run.addr),
                                  hex(run.size),
                                  "-", "-", "-", "unallocated"])

                # large run
                elif run.binind in [0xff, 0x1fe0]:
                    table.append([i,
                                  hex(run.addr),
                                  hex(run.size),
                                  "-", "-", "-", "large"])

                # small run
                else:
                    table.append([i,
                                  hex(run.addr),
                                  hex(run.size),
                                  hex(jeheap.bin_info[run.binind].reg_size),
                                  jeheap.bin_info[run.binind].nregs,
                                  run.nfree,
                                  "small"])
            elif not run.binind in [0xff, 0x1fe0] and size_class == jeheap.bin_info[run.binind].reg_size:
                table.append([i,
                              hex(run.addr),
                              hex(run.size),
                              hex(jeheap.bin_info[run.binind].reg_size),
                              jeheap.bin_info[run.binind].nregs,
                              run.nfree,
                              "large"])

        table = sorted(table, key=lambda x: x[1])

        i = 1
        for line in table:
            line[0] = i
            i += 1

        table = [("*", "run_addr", "run_size", "region_size", "no_regions", "no_free", "type")] + table
        print(ascii_table(table))


def dump_bins():
    global jeheap

    if dbg_engine == "pykd":
        path = os.path.join(storage_path, "jeheap")
        jeheap = load_jeheap(path)

    if not jeheap:
        print("[shadow] Parsed heap object not found, use jeparse.")
        return

    for arena in jeheap.arenas:
        table = [("index", "addr", "size", "runcur")]
        print("arena @ 0x%x" % arena.addr)
        for jebin in arena.bins:
            size = '-'
            addr = '-'
            if jebin.runcur:
                size = hex(jeheap.bin_info[jebin.index].reg_size)
                addr = hex(jebin.runcur.hdr_addr)
            table.append((jebin.index,
                          hex(jebin.addr),
                          size,
                          addr))
        print(ascii_table(table))


def dump_tcaches():
    global jeheap

    if not jeheap:
        print("[shadow] Parsed heap object not found, use jeparse.")
        return

    table = [("tid", "address", "tbins")]

    for tid,tcache in jeheap.tcaches.items():
        tid = int(tid)

        if not tcache:
            addr = "-"
            tbins = "-"
        else:
            addr = hex(tcache.addr)
            tbins = len(tcache.tbins)
        table.append((tid,
                      addr,
                      tbins))

    print(ascii_table(table))


def dump_tcache(tid, binind, size):
    global jeheap

    if not jeheap:
        print("[shadow] Parsed heap object not found, use jeparse.")
        return

    k = str(tid)
    if k not in jeheap.tcaches:
        print("[shadow] No tcache for thread %d" % tid)
        return

    tcache = jeheap.tcaches[k]
    if not tcache:
        print("[shadow] No tcache for thread %d" % tid)
        return

    # summary of all tbins
    if binind is None and size is None:
        table = [("index", "lg_fill_div", "ncached", "low_water", "ncached_max")]
        for tb in tcache.tbins:
            table.append((tb.index, tb.lg_fill_div,
                          tb.ncached, hex(tb.low_water),
                          jeheap.tbin_info[tb.index].ncached_max))

        print(ascii_table(table))
        return


    # otherwise print details of a specific tbin

    # use size to get the binind if the size argument was provided
    # (ignoring the binind argument)
    if size:
        binind = size2binind(jeheap, size)

    if binind is None:
        print("[shadow] Size argument doesn't match to a bin index.")
        return

    if binind < 0 or binind >= jeheap.nbins:
        print("[shadow] Invalid bin index.")
        return

    tb = tcache.tbins[binind]

    table = [("index", "lg_fill_div", "ncached", "low_water", "ncached_max")]
    table.append((tb.index, tb.lg_fill_div,
                  tb.ncached, hex(tb.low_water),
                  jeheap.tbin_info[tb.index].ncached_max))
    print(ascii_table(table))
    print("")

    table = [("stack",)]
    for region_address in tb.stack:
        table.append((hex(region_address),))
    print(ascii_table(table))
    return


def dump_regions(size_class):
    global jeheap

    if dbg_engine == "pykd":
        path = os.path.join(storage_path, "jeheap")
        jeheap = load_jeheap(path)

    if not jeheap:
        print("[shadow] Parsed heap object not found, use jeparse.")
        return

    runs = []
    for k,v in jeheap.runs.items():
        run = v

        if run.binind == 0xff:
            continue

        if jeheap.bin_info[run.binind].reg_size != size_class:
            continue

        runs.append(run)

    table = []
    for run in runs:
        run_addr = hex(run.addr)
        run_size = hex(run.size)
        no_free = run.nfree
        no_regions = jeheap.bin_info[run.binind].nregs
        run_usage = "%d/%d" % (no_regions - no_free, no_regions)
        reg_size = jeheap.bin_info[run.binind].reg_size

        table.append([0, run_addr, reg_size, run_size, run_usage])

    table = sorted(table, key = lambda x: x[1])
    i = 1
    for line in table:
        line[0] = i
        i += 1

    table = [("*", "run_addr", "reg_size", "run_size", "usage")] + table
    print(ascii_table(table))


def dump_run(addr, view_maps=False):
    global jeheap

    if dbg_engine == "pykd":
        path = os.path.join(storage_path, "jeheap")
        jeheap = load_jeheap(path)

    k = str(addr)
    if k not in jeheap.runs:
        # search in case the user specified the run's body address
        found = False
        for _,run in jeheap.runs.items():
            if run.addr == addr:
                k = str(run.hdr_addr)
                found = True
                break
        if not found:
            print('[shadow] run 0x%x not found' % addr)
            return

    run = jeheap.runs[k]

    # large run
    if len(run.regions) == 0:
        table = [("address", "size")]
        table.append((hex(run.addr), hex(run.size)))
        print(ascii_table(table))
        return

    # read the content preview
    if dbg_engine and not run.regions[0].data:
        n_dwords = run.size // jeheap.dword_size
        run_mem = dbg.read_dwords(run.addr, n_dwords)

        for reg in run.regions:
            i = (reg.addr - run.addr) // jeheap.dword_size
            reg.data = run_mem[i]

    # map content preview to heap metadata or a loaded module
    if (view_maps and
        run.regions[0].data is not None and
        not run.regions[0].data_map):

        modules_dict = jeheap.modules_dict

        for region in run.regions:
            # map to heap
            addr_info = find_address(region.data, jeheap)

            if addr_info.chunk:
                if addr_info.region:
                    region.data_map = '0x%x region' % addr_info.region.size
                    continue
                elif addr_info.run:
                    region.data_map = '0x%x run' % addr_info.run.size
                    continue

            # map to module
            for name, range_list in modules_dict.items():
                if region.data_map:
                    break
                for a_range in range_list:
                    start = a_range[0]
                    end = a_range[1]
                    if start <= region.data < end:
                        module_start = range_list[0][0]
                        offset = region.data - module_start
                        mapping = '%s + 0x%x' % (name, offset)
                        region.data_map = mapping
                        break

            # nothing found
            if not region.data_map:
                region.data_map = '-'

    if view_maps:
        table = [("*", "status", "address", "preview", "map")]
    else:
        table = [("*", "status", "address", "preview")]

    data_fmt_str = "%" + ("0%d" % (jeheap.dword_size * 2)) + "x"
    for region in run.regions:
        if region.is_free:
            status = "free"
        else:
            status = "used"
        if view_maps:
            table.append((region.index,
                          status,
                          hex(region.addr),
                          data_fmt_str % region.data,
                          region.data_map))
        else:
            table.append((region.index,
                          status,
                          hex(region.addr),
                          data_fmt_str % region.data))

    print(ascii_table(table))


def dump_address(addr):
    global jeheap

    if dbg_engine == "pykd":
        path = os.path.join(storage_path, "jeheap")
        jeheap = load_jeheap(path)

    if not jeheap:
        print("[shadow] Parsed heap object not found, use jeparse.")
        return

    addr_info = find_address(addr, jeheap)

    # address doesn't belong to a heap
    if not addr_info.chunk:
        # address doesn't belong to a module either
        if not addr_info.module:
            print("[shadow] Nothing found.")
            return

        # address belongs to a module
        table = [("module", "offset")]
        table.append((addr_info.module, hex(addr_info.module_off)))
        print(ascii_table(table))
        return

    # address belongs to the heap
    chunk = addr_info.chunk
    run = addr_info.run
    region = addr_info.region

    table = [("parent", "address", "size")]
    table.append(("arena", hex(chunk.arena_addr), "-"))
    table.append(("chunk", hex(chunk.addr), hex(jeheap.chunk_size)))
    if run:
        table.append(("run", hex(run.addr), hex(run.size)))
        if region:
            table.append(("region", hex(region.addr), hex(region.size)))

    print(ascii_table(table))


def parse_nursery():
    '''Parse the current SpiderMonkey's JSRuntime GC nursery'''
    global dbg_engine
    global nursery_heap

    nursery_expr = "xul!nsXPConnect::gSelf->mContext->mJSContext->runtime_.value->gc.nursery_.value"
    nursery_expr_old = "xul!nsXPConnect::gSelf->mRuntime->mJSRuntime->gc.nursery"

    ver = int(dbg.get_xul_version().split('.')[0])

    # XXX: check which version actually changed the nursery class
    if ver >= 53:

        lines = dbg.eval_expr(nursery_expr).split('\n')

        if dbg_engine == 'pykd':
            for line in lines:
                if line.find('runtime_') != -1:
                    start = line.find(': 0x')
                    subline = line[(start + 2):]
                    end = subline.find(' ')
                    nursery_heap.jsruntime_addr = dbg.to_int(subline[:end])
                    continue

                if line.find('position_') != -1:
                    start = line.find(': 0x')
                    subline = line[(start + 2):]
                    nursery_heap.next_free_addr = dbg.to_int(subline)
                    continue

                if line.find('currentStartPosition_') != -1:
                    start = line.find(': 0x')
                    subline = line[(start + 2):]
                    nursery_heap.start_addr = dbg.to_int(subline)
                    continue

                if line.find('currentEnd_') != -1:
                    start = line.find(': 0x')
                    subline = line[(start + 2):]
                    nursery_heap.end_addr = dbg.to_int(subline)
                    continue

        elif dbg_engine == 'gdb':
            # XXX: not implemented yet
            pass
        else: # lldb
            # XXX: not implemented yet
            pass

        nursery_heap.size = nursery_heap.end_addr - nursery_heap.start_addr

    else:

        lines = dbg.eval_expr(nursery_expr_old).split('\n')

        if dbg_engine == 'pykd':
            for line in lines:
                if line.find('runtime_') != -1:
                    start = line.find(': 0x')
                    subline = line[(start + 2):]
                    end = subline.find(' ')
                    nursery_heap.jsruntime_addr = dbg.to_int(subline[:end])
                    continue

                if line.find('position_') != -1:
                    start = line.find(': 0x')
                    subline = line[(start + 2):]
                    nursery_heap.next_free_addr = dbg.to_int(subline)
                    continue

                if line.find('heapStart_') != -1:
                    start = line.find(': 0x')
                    subline = line[(start + 2):]
                    nursery_heap.start_addr = dbg.to_int(subline)
                    continue

                if line.find('heapEnd_') != -1:
                    start = line.find(': 0x')
                    subline = line[(start + 2):]
                    nursery_heap.end_addr = dbg.to_int(subline)
                    continue

        elif dbg_engine == 'gdb':
            # XXX: not implemented yet
            pass
        else: # lldb
            # XXX: not implemented yet
            pass

        nursery_heap.size = nursery_heap.end_addr - nursery_heap.start_addr


def dump_nursery():
    '''Display info on the current SpiderMonkey's JSRuntime GC nursery'''

    global nursery_heap

    parse_nursery()
    print(nursery_heap)


def pwnarray(addr, new_length = 0x666):
    '''Modify the array's (ArrayObject) initlen, capacity and length in memory'''

    global dbg_engine

    if dbg_engine == 'pykd':
        # modify the ArrayObject's initial length
        dbg.execute('ed %x %x' % (addr + 0x4, new_length))

        # modify the ArrayObject's capacity
        dbg.execute('ed %x %x' % (addr + 0x8, new_length))

        # modify the ArrayObject's length
        dbg.execute('ed %x %x' % (addr + 0xc, new_length))

        print('[shadow] ArrayObject at 0x%x:' % (addr))

        for line in lines:
            if line != '':
                print('[shadow] %s' % (line))

    elif dbg_engine == 'gdb':
        # XXX: not implemented yet
        pass

    else: # lldb
        # XXX: not implemented yet
        pass



def find_address(addr, jeheap):
    addr_info = jemalloc.address_info()
    addr_info.addr = addr

    # find the chunk it belongs to
    for chunk in jeheap.chunks:
        if chunk.addr <= addr < chunk.addr + jeheap.chunk_size:
            addr_info.chunk = chunk
            break

    if not addr_info.chunk:
        # check if the address belongs to a module
        modules = jeheap.modules_dict
        found = False
        for name, range_list in modules.items():
            for a_range in range_list:
                start = a_range[0]
                end = a_range[1]
                if start <= addr < end:
                    module_start = range_list[0][0]
                    off = addr - module_start
                    addr_info.module = name
                    addr_info.module_off = off
                    found = True
                    break
            if found:
                break

        return addr_info

    # search the runs
    for run_addr in addr_info.chunk.runs:
        run = jeheap.runs[str(run_addr)]
        if run.addr <= addr < run.addr + run.size:
            addr_info.run = run
            break

    if not addr_info.run:
        return addr_info

    # find if it belongs to a region
    for region in addr_info.run.regions:
        if region.addr <= addr < region.addr + region.size:
            addr_info.region = region
            break

    if not addr_info.region:
        return addr_info

    # XXX: tcache search
    return addr_info


def dump_symbol(size, has_vtable=False, from_mozjs=True, from_xul=False,
                from_dom=False):
    '''Display information on Firefox-specific symbols'''

    global xul_symbols_pickle

    dom_prefix = 'mozilla::dom::'
    js_prefix = 'js::'

    pfd = open(xul_symbols_pickle, 'rb')
    xul_symbols = pickle.load(pfd)
    pfd.close()

    if from_mozjs == True:
        if has_vtable == False:
            print('[shadow] Searching for SpiderMonkey symbols of size %d' % (size))
        else:
            print('[shadow] Searching for SpiderMonkey class symbols of size %d with vtable' \
                  % (size))

        for sym in xul_symbols:
            if not sym.name.startswith(js_prefix):
                continue

            if size == sym.size:
                if has_vtable == True:
                    if sym.kind == 'class' and sym.has_vtable == True:
                        print('[shadow] %s' % (sym))
                else:
                    print('[shadow] %s' % (sym))

    if from_xul == True or from_dom == True:
        if has_vtable == False:
            if from_dom == True:
                print('[shadow] Searching for DOM symbols of size %d' % (size))
            else:
                print('[shadow] Searching for non-SpiderMonkey symbols of size %d' % (size))
        else:
            if from_dom == True:
                print('[shadow] Searching for DOM class symbols of size %d with vtable' % (size))
            else:
                print('[shadow] Searching for non-SpiderMonkey class symbols of size %d with vtable' \
                      % (size))

        for sym in xul_symbols:
            if sym.name.startswith(js_prefix):
                continue

            if size == sym.size:
                if has_vtable == True:
                    if sym.kind == 'class' and sym.has_vtable == True:
                        if from_dom == True:
                            if sym.name.startswith(dom_prefix):
                                print('[shadow] %s' % (sym))
                        else:
                            print('[shadow] %s' % (sym))
                else:
                    if from_dom == True:
                        if sym.name.startswith(dom_prefix):
                            print('[shadow] %s' % (sym))
                    else:
                        print('[shadow] %s' % (sym))


# search functions
def subfinder(pattern, mylist):
    matches = []
    for i in range(len(mylist)):
        if mylist[i] == pattern[0] and mylist[i:i+len(pattern)] == pattern:
            # matches.append(pattern)
            matches.append(i)
    return matches


def int2list(i):
    li = []
    while i != 0:
        li.append(i & 0xff)
        i = i >> 8
    return li


def to_list(val):
    if type(val) is str:
        return [ord(c) for c in val]
    if type(val) is int:
        return int2list(val)

    # XXX: find a better way to do this
    try:
        # python2
        if type(val) is long:
            return int2list(val)
    except:
        # python3
        pass

    if type(val) is tuple:
        return list(val)
    if type(val) is bytearray:
        return list(val)
    if type(val) is unicode:
        return list(val)
    if type(val) is list:
        return val
    return None


def search_cur_runs(jeheap, search_for, size_class):
    matches = []
    for arena in jeheap.arenas:
        for abin in arena.bins:
            if not abin.runcur:
                continue

            run = abin.runcur
            run_mem = dbg.read_bytes(abin.runcur.addr, abin.runcur.size)
            run_mem = to_list(run_mem)
            for off in subfinder(search_for, run_mem):
                matches.append(abin.runcur.addr + off)

    return matches


def search_heap(jeheap, search_for, size_class):
    matches = []

    for chunk in jeheap.chunks:
        chunk_mem = dbg.read_bytes(chunk.addr, jeheap.chunk_size)
        chunk_mem = to_list(chunk_mem)

        for off in subfinder(search_for, chunk_mem):
            matches.append(chunk.addr + off)

    return matches


def search_addr_space(jeheap, search_for):
    matches = []
    for k,v in jeheap.modules_dict.items():
        for (start, end) in v:
            # print("searching 0x%x-0x%x" %(start, end))
            try:
                mem = dbg.read_bytes(start, end - start)
            except:
                # print("skipping...")
                continue

            for off in subfinder(search_for, mem):
                matches.append(start + off)

    return matches


def search(search_for, size_class, search_current_runs, search_address_space):
    global jeheap

    if dbg_engine == "pykd":
        path = os.path.join(storage_path, "jeheap")
        jeheap = load_jeheap(path)

    if not jeheap:
        print("[shadow] Parsed heap object not found, use jeparse.")
        return

    # no whitespace
    if len(search_for) == 1:
        search_for = search_for[0]
        # "" string
        if search_for.startswith("\""):
            if not search_for.endswith("\""):
                print("[shadow] End of string not found.")
                return
            search_for = str(search_for[1:-1])

        # '' string
        elif search_for.startswith("'"):
            if not search_for.endswith("'"):
                print("[shadow] End of string not found.")
                return
            search_for = str(search_for[1:-1])

        # hex number
        else:
            search_for = int(search_for, 16)
    else:
        # this strings approach is not correct because there might
        # be more than one space between the arguments

        # "" string
        if search_for[0].startswith("\""):
            if not search_for[-1].endswith("\""):
                print("[shadow] End of string not found.")
                return
            search_for[0] = search_for[0][1:]
            search_for[-1] = search_for[-1][:-1]
            s = ""
            for elm in search_for:
                s += str(elm)
                s += " "
            search_for = s

        # '' string
        elif search_for[0].startswith("'"):
            if not search_for[-1].endswith("'"):
                print("[shadow] End of string not found.")
                return
            search_for[0] = search_for[0][1:]
            search_for[-1] = search_for[-1][:-1]
            s = ""
            for elm in search_for:
                s += str(elm)
                s += " "
            search_for = s

        else:
            search_for = [int(i, 16) for i in search_for]

    # convert to list
    search_for = to_list(search_for)

    matches = []
    # search current runs only
    if search_address_space:
        matches = search_addr_space(jeheap, search_for)
    elif search_current_runs:
        matches =  search_cur_runs(jeheap, search_for, size_class)
    # search everything
    else:
        matches = search_heap(jeheap, search_for, size_class)

    table = [("address", "run", "region", "region size", "arena")]
    for addr in matches:
        info = find_address(addr, jeheap)
        if info.run:
            run_addr = hex(info.run.addr)
        else:
            run_addr = "-"

        if info.region:
            region_addr = hex(info.region.addr)
            region_size = hex(info.region.size)
        else:
            region_addr = "-"
            region_size = "-"

        if info.chunk:
            arena_info = "0x%x" % info.chunk.arena_addr
        else:
            arena_info = "-"


        table.append((hex(addr), run_addr,
                      region_addr, region_size,
                      arena_info))

    print(ascii_table(table))



# standalone usage
def main():
    argc = len(sys.argv)
    if argc < 3:
        print('[shadow] /path/to/snapshot command ...')
        return

    snapshot_path = sys.argv[1]
    cmd = sys.argv[2]
    args = sys.argv[3:]

    global jeheap
    jeheap = jemalloc.jemalloc(snapshot_path)

    if cmd == 'jechunks':
        dump_chunks()

    elif cmd == "jechunk":
        try:
            if len(args) >= 1:
                if args[0].startswith("0x"):
                    addr = int(args[0], 16)
                else:
                    addr = int("0x%s" % args[0], 16)
        except:
            print('[shadow] usage: jechunk <address>')
            print('[shadow] for example: jechunk 0x900000')
            return

        dump_chunk(addr)

    elif cmd == 'jeruns':
        if len(args) >= 1 and args[0] == '-c':
            current_runs = True
        else:
            current_runs = False

        if len(args) >= 2:
            if args[1].startswith('0x'):
                size_class = int(args[1], 16)
            else:
                size_class = int(args[1])
        else:
            size_class = 0
        dump_runs(dump_current_runs=current_runs, size_class=size_class)

    elif cmd == 'jerun':
        if len(args) >= 2 and args[0] == '-m':
            view_maps = True
            addr = args[1]
        elif len(args) == 1:
            view_maps = False
            addr = args[0]
        else:
            print('[shadow] usage: jerun <address>')
            print('[shadow] usage: jerun -m <address>')
            print('[shadow] for example: jerun 0x087e1000')
            return

        try:
            if addr.startswith('0x'):
                addr = int(addr, 16)
            else:
                addr = int('0x%s' % addr, 16)
        except:
            print('[shadow] invalid address paremeter')
            return

        dump_run(addr, view_maps)

    elif cmd == 'jeinfo':
        try:
            if args[0].startswith('0x'):
                addr = int(args[0], 16)
            else:
                addr = int(args[0])
        except:
            print('[shadow] usage: jeinfo <address>')
            print('[shadow] for example: jeinfo 0x079e5440')
            return

        dump_address(addr)

    elif cmd == 'jebins':
        dump_bins()

    elif cmd == 'jearenas':
        dump_arenas()

    elif cmd == 'jeregions':
        if len(args) == 0:
            print('[shadow] usage: jeregions <size class>')
            print('[shadow] for example: jeregions 1024')
            return
        if args[0].startswith('0x'):
            size_class = int(args[0], 16)
        else:
            size_class = int(args[0])
        dump_regions(size_class)

    elif cmd == 'jedump':
        if len(args) == 0:
            screen = True
        else:
            screen = False
        dump_all(filename=args[0],
                 dump_to_screen=screen)


def ascii_table(tuples_list, header=True):
    # find the bigger tuple in the list
    max_len = max(len(t) for t in tuples_list)

    # find out the max len of each column element
    max_element_len = [0] * max_len
    for i in range(0, max_len):
        # str(t[i]) gets the wrong length of DMLStrings
        # values = (str(t[i]) for t in tuples_list)
        values = (str(t[i]) for t in tuples_list)
        max_element_len[i] = max(len(v) for v in values)

    list_body = tuples_list

    out = ""

    # table header
    if header is True:
        list_body = tuples_list[1:]
        line_len = 0
        header_tuple = tuples_list[0]
        for i in range(0, len(header_tuple)):
            if i == 0:
                spacing = 0
            else:
                spacing = 4
            align = (max_element_len[i] - len(str(header_tuple[i])))
            out += " " * spacing + str(header_tuple[i]) + " " * align
    out += "\n"

    # print header seperator line
    line_len = sum(l + 4 for l in max_element_len)
    out += "-" * line_len
    out += "\n"

    # print the rest of the table
    for t in list_body:
        for i in range(0, len(t)):
            if i == 0:
                spacing = 0
            else:
                spacing = 4
            # align = (max_element_len[i] - len(str(t[i])))
            align = max_element_len[i] - len(str(t[i]))
            out +=  " " * spacing
            out += str(t[i])
            out += " " * align
        out += "\n"

    return out

if __name__ == '__main__':
    main()
# EOF
