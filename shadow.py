# shadow - De Mysteriis Dom Firefox

import os
import sys
import warnings
import cPickle as pickle
import time
import datetime
import copy
import tempfile

sys.path.append('.')

import jemalloc
import nursery
import symbol

VERSION = 'v1.0b'

true = True
false = False
none = None

# globals
jeheap = jemalloc.jemalloc()
nursery_heap = nursery.nursery()
parsed = false
dbg_engine = ''
pickle_file = ''
xul_symbols_pickle = ''
xul_version = ''

try:
    import gdb
    import gdb_engine as dbg
    dbg_engine = 'gdb'
    pickle_file = '/tmp/jeheap.pkl'
except ImportError:
    try:
        import pykd
        import pykd_engine as dbg
        dbg_engine = 'pykd'
        pickle_file = '%s/%s' % (tempfile.gettempdir(), 'jeheap.pkl')
        xul_version = dbg.get_xul_version();
        xul_symbols_pickle = '%s\\pdb\\xul-%s.pdb.pkl' \
            % (os.path.dirname(os.path.abspath(__file__)), xul_version)
    except ImportError:
        try:
            import lldb
            import lldb_engine as dbg
            dbg_engine = 'lldb'
            pickle_file = '/tmp/jeheap.pkl'
        except ImportError:
            print('[shadow] error: only usable from within gdb or windbg/pykd or lldb')
            sys.exit()

# print a timestamp
def print_timestamp():
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    print('[shadow] %s' % (st))

# serialize the jeheap object to a pickle
def pickle_dump():
    global jeheap
    global pickle_file

    if os.path.islink(pickle_file) == true:
        print('[shadow] error: %s is a symbolic link' % (pickle_file))
        sys.exit()

    pickle_fd = open(pickle_file, 'wb')
    pickle.dump(jeheap, pickle_fd)
    pickle_fd.close()

# deserialize (load) the jeheap object from a pickle
def pickle_load():
    global jeheap
    global pickle_file

    if os.path.islink(pickle_file) == true:
        print('[shadow] error: %s is a symbolic link' % (pickle_file))
        sys.exit()

    pickle_fd = open(pickle_file, 'rb')
    jeheap = pickle.load(pickle_fd)
    pickle_fd.close()

# load the jeheap from a pickle or re-parse it
def load_jeheap(proc = none):
    global pickle_file
    global parsed
    
    if os.path.isfile(pickle_file) == true:
        pickle_load()
    else:
        if parsed == false:
            parse(proc)

# parse jemalloc configuration options
def parse_options():
    global jeheap

    # thread magazine caches (disabled on firefox)
    try:
        opt_mag = dbg.get_value('opt_mag')
    except:
        opt_mag = 0

    try:
        opt_tcache = dbg.get_value('opt_tcache')
    except:
        opt_tcache = 0

    try:
        opt_lg_tcache_nslots = \
            dbg.get_value('opt_lg_tcache_nslots')
    except:
        opt_lg_tcache_nslots = 0

    if opt_mag != 0 or opt_tcache != 0 or opt_lg_tcache_nslots != 0:
        jeheap.MAGAZINES = true

    if jeheap.MAGAZINES == true:
        try:
            mag_rag_t_size = dbg.sizeof('mag_rack_t')
            bin_mags_t_size = dbg.sizeof('bin_mags_t')
                
            jeheap.magrack_size = \
                    mag_rag_t_size + (bin_mags_t_size * (jeheap.nbins - 1))

        except:
            # standalone variant
            jeheap.STANDALONE = true

            tcache_t_size = dbg.sizeof('tcache_t')
            tcache_bin_t_size = dbg.sizeof('tcache_bin_t')

            jemalloc.magrack_size = \
                    tcache_t_size + (tcache_bin_t_size * (jeheap.nbins - 1))

# parse general jemalloc information
def parse_general():
    global jeheap

    try:
        jeheap.narenas = dbg.to_int(dbg.get_value('narenas'))
    except:
        print('[shadow] error: symbol narenas not found')
        sys.exit()

    try:
        jeheap.nbins = dbg.to_int(dbg.get_value('nbins'))
    except:
        # XXX: these are firefox specific, we must add support for more
        #      jemalloc variants in the future
        if sys.platform == 'darwin' or sys.platform == 'win32':
            jeheap.ntbins = dbg.to_int(dbg.get_value('ntbins'))
            jeheap.nsbins = dbg.to_int(dbg.get_value('nsbins'))
            jeheap.nqbins = dbg.to_int(dbg.get_value('nqbins'))
            jeheap.nbins = jeheap.ntbins + jeheap.nsbins + jeheap.nqbins
        else:
            if jeheap.DWORD_SIZE == 4:
                jeheap.nbins = 36
            elif jeheap.DWORD_SIZE == 8:
                jeheap.nbins = 35

    # XXX: figure out how to calculate the chunk size correctly, this is
    #      firefox specific
    jeheap.chunk_size = 1 << 20

# parse jemalloc arena information
def parse_arenas():
    global jeheap

    jeheap.arenas[:] = []

    for i in range(0, jeheap.narenas):
        current_arena = jemalloc.arena(0, i, [])

        try:
            current_arena.addr = \
                dbg.to_int(dbg.eval_expr(dbg.arena_expr % (i)))
        except:
            print('[shadow] error: cannot evaluate arenas[%d]') % (i)
            sys.exit()

        for j in range(0, jeheap.nbins):
            nrg = 0
            run_sz = 0
            reg_size = 0
            reg_offset = 0
            end_addr = 0

            try:
                expr = dbg.arena_reg_size_expr % (i, j)
                reg_size = dbg.to_int(dbg.eval_expr(expr))
               
                expr = dbg.arena_reg0_offset_expr % (i, j)
                reg_offset = dbg.to_int(dbg.eval_expr(expr))

            except:
                # XXX: for now assume it's a standalone variant; we
                #      need to do some error checking here too.
                jeheap.STANDALONE = true

                expr = dbg.arena_bin_info_reg_size_expr % (j)
                reg_size = dbg.to_int(dbg.eval_expr(expr))

                expr = dbg.arena_bin_info_nregs_expr % (j)
                nrg = dbg.to_int(dbg.eval_expr(expr))

                expr = dbg.arena_bin_info_run_size_expr % (j)
                run_sz = dbg.to_int(dbg.eval_expr(expr))

            try:
                expr = dbg.arena_runcur_expr % (i, j)
                runcur_addr = runcur = dbg.to_int(dbg.eval_expr(expr))

                end_addr = runcur_addr + run_sz

                if runcur != 0:
                    current_run = \
                        jemalloc.arena_run(runcur, end_addr, run_sz, 0, \
                            int(reg_size), reg_offset, nrg, 0, [])

                    current_bin = jemalloc.arena_bin(0, j, current_run)

                    current_bin.addr = \
                        dbg.to_int(dbg.eval_expr(dbg.arena_bin_addr_expr % (i, j)))

                    current_arena.bins.append(current_bin)

                else:
                    # no regions for this size class yet, therefore no runcur
                    current_run = jemalloc.arena_run()
                    current_bin = jemalloc.arena_bin(0, j, current_run)
                    current_arena.bins.append(current_bin)

            except:
                current_run = jemalloc.arena_run()
                current_bin = jemalloc.arena_bin(0, j, current_run)
                current_arena.bins.append(current_bin)
                continue

        # add arena to the list of arenas
        jeheap.arenas.append(current_arena)

def parse_run(run_addr, proc = none):
    '''Given a run's address return a jemalloc.arena_run object'''

    global jeheap

    new_run = jemalloc.arena_run()
    new_run.start = run_addr
    
    try:
        new_run.bin_addr = dbg.read_memory(new_run.start, jeheap.DWORD_SIZE, proc)

        if jeheap.STANDALONE == false:
            new_run.size = dbg.read_memory(new_run.bin_addr + \
                    (6 * jeheap.DWORD_SIZE), jeheap.DWORD_SIZE, proc)

            new_run.end = new_run.start + new_run.size

            new_run.region_size = dbg.read_memory(new_run.bin_addr + \
                    (5 * jeheap.DWORD_SIZE), jeheap.DWORD_SIZE, proc)

            new_run.total_regions = dbg.read_memory(new_run.bin_addr + \
                    (7 * jeheap.DWORD_SIZE), jemalloc.INT_SIZE, proc)
            
            if new_run.total_regions > 10000 or new_run.total_regions <= 0:
                return none
    except:
        # print('[shadow] error parsing the metadata of run 0x%08x' % (run_addr))
        return none

    # XXX: this isn't correct on jemalloc standalone *debug* variant
    try:
        new_run.free_regions = dbg.read_memory(new_run.start + \
                jeheap.DWORD_SIZE + jemalloc.INT_SIZE, jemalloc.INT_SIZE, proc)
    except:
        # print('[shadow] error parsing the free regions of run 0x%08x' % (run_addr))
        new_run.free_regions = 0

    if new_run.free_regions < 0:
        new_run.free_regions = 0

    # delete the run's regions
    new_run.regions[:] = []

    # parse the run's regions
    new_run.reg0_offset = dbg.read_memory(new_run.bin_addr + \
            (9 * jeheap.DWORD_SIZE), jeheap.DWORD_SIZE, proc)

    if new_run.reg0_offset > 10000 or new_run.reg0_offset <= 0:
        return none

    first_region_addr = reg0_addr = run_addr + new_run.reg0_offset
    regs_mask_bits = (new_run.total_regions / 8) + 1

    regs_mask_addr = 0
    regs_mask_str = ''

    if dbg_engine == 'gdb':
        regs_mask_addr = dbg.to_int(dbg.execute(dbg.regs_mask_addr_expr % \
                (run_addr)))

        regs_mask_str = dbg.execute(dbg.regs_mask_addr_bits_expr % \
                (regs_mask_bits, regs_mask_addr))

    elif dbg_engine == 'pykd':
        regs_mask_addr = dbg.to_int(dbg.eval_expr(dbg.regs_mask_addr_expr % \
                (run_addr)))

        regs_mask_str = dbg.execute(dbg.regs_mask_addr_bits_expr % \
                (regs_mask_addr, regs_mask_bits))

    else: # lldb
        regs_mask_str = ''

    regs_mask = ''

    if dbg_engine == 'gdb':

        for line in regs_mask_str.splitlines():
            line = line[line.find(dbg.address_separator) + \
                    len(dbg.address_separator) : line.find('\n')]

            line = line.replace('\n', '')
            line = line.replace('\t', '')
            line = line.replace(' ', '')

            regs_mask += line

    elif dbg_engine == 'pykd':

        lines = regs_mask_str.splitlines()
        lines = lines[2:]

        for line in lines:
            line = line[line.find(dbg.address_separator) + \
                    len(dbg.address_separator) : \
                    line.rfind(dbg.address_separator)]

            line = line.replace('\n', '')
            line = line.replace('\t', '')
            line = line.replace(' ', '')

            regs_mask += line

    else: # lldb
        regs_mask = ''

    new_run.regs_mask = regs_mask

    first_region = jemalloc.region(0, first_region_addr, \
            int(new_run.regs_mask[0]))

    try:
        first_region.content_preview = hex(dbg.read_memory(first_region.addr, \
                jemalloc.INT_SIZE, proc)).rstrip('L')
    except:
        print('[shadow] error reading the first dword of region 0x%08x' \
                % (first_region.addr))

        first_region.content_preview = ''

    new_run.regions.append(first_region)

    for i in range(1, new_run.total_regions):
        try:
            current_region = jemalloc.region(i, 0, int(new_run.regs_mask[i]))
        except:
            current_region = jemalloc.region(i, 0, 0)

        current_region.addr = reg0_addr + (i * new_run.region_size)

        try:
            current_region.content_preview = \
                    hex(dbg.read_memory(current_region.addr, jemalloc.INT_SIZE, proc)).rstrip('L')
        except:
            current_region.content_preview = ''

        new_run.regions.append(current_region)

    return new_run

# parse the metadata of all runs and their regions
def parse_all_runs(proc = none):
    global jeheap
    global dbg_engine

    # number of pages a chunk occupies
    chunk_npages = jeheap.chunk_size >> 12

    # offset of bits in arena_chunk_map_t in double words
    if dbg_engine == 'pykd':
        # this really speeds up parsing
        bitmap_offset = \
            dbg.offsetof('mozglue!arena_chunk_map_t', 'bits') / jeheap.DWORD_SIZE
    else:
        bitmap_offset = \
            dbg.offsetof('arena_chunk_map_t', 'bits') / jeheap.DWORD_SIZE

    # number of double words occupied by an arena_chunk_map_t
    chunk_map_dwords = (bitmap_offset / jeheap.DWORD_SIZE) + 1

    if jeheap.DWORD_SIZE == 8:
        if dbg_engine == 'gdb':
            dword_fmt = 'g'
        else: # lldb
            dw_fmt = 'XXX'
    else:
        if dbg_engine == 'gdb':
            dword_fmt = 'w'
        else: # lldb
            dw_fmt = 'XXX'

    # the 12 least significant bits of each bitmap entry hold
    # various flags for the corresponding run
    flags_mask = (1 << 12) - 1

    # delete the heap's runs' array
    jeheap.runs[:] = []

    for chunk in jeheap.chunks:
        if not chunk.arena_addr:
            continue

        try:
            if dbg_engine == 'gdb':
                # parse the whole map at once to avoid gdb's delays
                expr = dbg.chunk_map_expr % \
                    (chunk_npages * chunk_map_dwords, dword_fmt, chunk.addr)

            elif dbg_engine == 'pykd':
                chunk_map_len = (chunk_npages * chunk_map_dwords) / 4
                chunk_map_addr = dbg.to_int(dbg.eval_expr(dbg.chunk_map_expr % (chunk.addr)))
                expr = dbg.chunk_map_dump_expr % (chunk_map_addr, chunk_map_len)
            else: # lldb
                expr = ''

        except:
            print('[shadow] error: cannot read bitmap from chunk 0x%08x' % (chunk.addr))
            sys.exit()

        lines = (dbg.execute(expr)).split('\n')

        dwords = []
        i = 0

        for line in lines:
            dwords += [int(dw, 16) for dw in \
                    line[line.find(dbg.address_separator) + \
                    len(dbg.address_separator):].split()]

        bitmap = [dwords[i] for i in range(int(bitmap_offset), \
                int(len(dwords)), int(bitmap_offset + 1))]

        # traverse the bitmap
        for mapelm in bitmap:
            flags = mapelm & flags_mask

            # flags == 1 means the chunk is small and the rest of the bits
            # hold the actual run address
            if flags == 1:
                addr = mapelm & ~flags_mask
                size = dbg.get_page_size()

            # flags = 3 indicates a large chunk; calculate the run's address
            # directly from the map element index and extract the run's size 
            elif flags == 3:
                addr = chunk.addr + i * dbg.get_page_size()
                size = mapelm & ~flags_mask

            # run is not allocated? skip it
            else:
                continue
    
            if addr not in [r.start for r in jeheap.runs]:
                new_run = parse_run(addr, proc)

                if new_run == none:
                    pass
                else:
                    jeheap.runs.append(copy.deepcopy(new_run))

# parse metadata of current runs and their regions
def parse_runs(proc = none):
    global jeheap

    for i in range(0, len(jeheap.arenas)):
        for j in range(0, len(jeheap.arenas[i].bins)):
            
            run_addr = jeheap.arenas[i].bins[j].run.start
            new_run = parse_run(run_addr, proc)

            if new_run == none:
                continue
            else:
                jeheap.arenas[i].bins[j].run = copy.deepcopy(new_run)

# parse all jemalloc chunks
def parse_chunks():
    global jeheap
    global dbg_engine

    # delete the chunks' list
    jeheap.chunks[:] = []

    try:
        root = dbg.to_int(dbg.eval_expr(dbg.chunk_rtree_root_expr))
        height = dbg.to_int(dbg.eval_expr(dbg.chunk_rtree_height_expr))

        level2bits = []

        for i in range(0, height):
            expr = dbg.chunk_rtree_level2bits_expr % (i)
            level2bits.append(dbg.to_int(dbg.eval_expr(expr)))
    except:
        print('[shadow] error: cannot parse chunk radix tree')
        sys.exit()

    # XXX: check if we're running on x86_64,
    #      not required for windbg/pykd (see the dp command)
    if jeheap.DWORD_SIZE == 8:
        if dbg_engine == 'gdb':
            dw_fmt = 'g'
        else: # lldb
            dw_fmt = 'XXX'
    else:
        if dbg_engine == 'gdb':
            dw_fmt = 'w'
        else: # lldb
            dw_fmt = 'XXX'

    # parse the radix tree using a stack
    stack = [(root, 0)]
    while len(stack):
        (node, node_height) = stack.pop()
        child_cnt = 1 << level2bits[node_height]
        
        if dbg_engine == 'gdb':
            expr = dbg.chunk_radix_expr % (child_cnt, dw_fmt, node)
        elif dbg_engine == 'pykd':
            child_cnt = child_cnt / 6 # XXX: is this correct on 64-bits?
            expr = dbg.chunk_radix_expr % (node, child_cnt)
        else: # lldb
            expr = ''

        dump = dbg.execute(expr)

        for line in dump.split('\n'):
            
            line = line[line.find(dbg.address_separator) + \
                    len(dbg.address_separator):]

            for address in line.split():
                try:
                    address = int(address, 16)
                except:
                    address = 0

                if address != 0:
                    # leaf nodes hold pointers to actual values
                    if node_height == height - 1:
                        expr = dbg.chunk_arena_expr % address
                        
                        try:
                            arena_addr = dbg.to_int(dbg.eval_expr(expr))
                        except:
                            arena_addr = 0
 
                        exists = false

                        if arena_addr in [i.addr for i in jeheap.arenas]:
                            exists = true

                        if exists:
                            jeheap.chunks.append(jemalloc.arena_chunk(address, arena_addr))
                        else:
                            jeheap.chunks.append(jemalloc.arena_chunk(address))

                    # non-leaf nodes are inserted in the stack
                    else:
                        stack.append((address, node_height + 1))

# our old workhorse, now broken in pieces
def parse(proc = none):
    '''Parse jemalloc structures from memory'''

    global jeheap
    global parsed

    parsed = false

    print('[shadow] parsing structures from memory...')
    print_timestamp()

    parse_options()
    parse_general()
    parse_arenas()
    parse_runs(proc)
    parse_chunks()
    parse_all_runs(proc)

    parsed = true
    pickle_dump()

    print('[shadow] structures parsed')
    print_timestamp()

def help():
    '''Details about the commands provided by shadow'''

    print('\n[shadow] De Mysteriis Dom Firefox')
    print('[shadow] %s\n' % (VERSION))
    print('[shadow] jemalloc-specific commands:')
    print('[shadow]   jechunks                : dump info on all available chunks')
    print('[shadow]   jearenas                : dump info on jemalloc arenas')
    print('[shadow]   jerun <address>         : dump info on a single run')
    print('[shadow]   jeruns [-cs]            : dump info on jemalloc runs')
    print('[shadow]                                 -c: current runs only')
    print('[shadow]                    -s <size class>: runs for the given size class only')
    print('[shadow]   jebins                  : dump info on jemalloc bins')
    print('[shadow]   jeregions <size class>  : dump all current regions of the given size class')
    print('[shadow]   jesearch [-cqs] <hex>   : search the heap for the given hex dword')
    print('[shadow]                                 -c: current runs only')
    print('[shadow]                                 -q: quick search (less details)')
    print('[shadow]                    -s <size class>: regions of the given size only')
    print('[shadow]   jeinfo <address>        : display all available details for an address')
    print('[shadow]   jedump [filename]       : dump all available jemalloc info to screen (default) or file')
    print('[shadow]   jeparse                 : parse jemalloc structures from memory')
    print('[shadow] Firefox-specific commands:')
    print('[shadow]   nursery                 : display info on the SpiderMonkey GC nursery')
    print('[shadow]   symbol [-vjdx] <size>   : display all Firefox symbols of the given size')
    print('[shadow]                                 -v: only class symbols with vtable')
    print('[shadow]                                 -j: only symbols from SpiderMonkey')
    print('[shadow]                                 -d: only DOM symbols')
    print('[shadow]                                 -x: only non-SpiderMonkey symbols')
    print('[shadow]   pa <address> [<length>] : modify the ArrayObject\'s length (default new length 0x666)')
    print('[shadow] Generic commands:')
    print('[shadow]   version                 : output version number')
    print('[shadow]   help                    : this help message')

def version():
    '''Output version number'''
    
    print('[shadow] %s' % (VERSION))

def dump_all(filename, dump_to_screen = true, proc = none):
    '''Dump all available jemalloc info to screen (default) or to a file'''
    
    global jeheap

    if dump_to_screen == true:
        print('[shadow] dumping all jemalloc info to screen')
    else:
        print('[shadow] dumping all jemalloc info to file %s' % (filename))

        if os.path.exists(filename):
            print('[shadow] error: file %s already exists' % (filename))
            return

        try:
            sys.stdout = open(filename, 'w')
        except:
            print('[shadow] error opening file %s for writing' % (filename))
            
    load_jeheap(proc)

    # general jemalloc info
    print(jeheap)
    print('')

    # info on chunks
    for chunk in jeheap.chunks:
        print(chunk)
            
    print('')

    # info on arenas
    for i in range(0, len(jeheap.arenas)):
        print(jeheap.arenas[i])
            
        print('')

        # info on current runs and bins
        print('[shadow] currents runs and their regions\n')

        for j in range(0, len(jeheap.arenas[i].bins)):
            print(jeheap.arenas[i].bins[j].run)
            print(jeheap.arenas[i].bins[j])

            # info on current regions
            for k in range(0, len(jeheap.arenas[i].bins[j].run.regions)):
                print(jeheap.arenas[i].bins[j].run.regions[k])

            print('')

        # info on non-current runs
        print('[shadow] non-currents runs\n')

        for j in range(0, len(jeheap.runs)):
            print('[shadow] [run 0x%08x] [size %07d]' % \
                    (jeheap.runs[j].start, jeheap.runs[j].size))

    # reset stdout
    if filename != '':
        sys.stdout = sys.__stdout__

def dump_chunks(proc = none):
    '''Dump info on all available chunks'''
    
    global jeheap

    load_jeheap(proc)

    for chunk in jeheap.chunks:
        print(chunk)

def dump_arenas(proc = none):
    '''Dump info on jemalloc arenas'''

    global jeheap

    load_jeheap(proc)
    print(jeheap)

def dump_runs(dump_current_runs = false, size_class = 0, proc = none):
    '''Dump info on jemalloc runs'''

    global jeheap
    
    load_jeheap(proc)

    if dump_current_runs == true:
        if size_class == 0:
            print('[shadow] listing current runs only')
        else:
            print('[shadow] listing current runs of size class %d' % (size_class))

        for i in range(0, len(jeheap.arenas)):
            print(jeheap.arenas[i])
    
            for j in range(0, len(jeheap.arenas[i].bins)):
                if size_class == 0:
                    print(jeheap.arenas[i].bins[j].run)
                else:
                    if size_class == jeheap.arenas[i].bins[j].run.region_size:
                        print(jeheap.arenas[i].bins[j].run)

    else:
        if size_class == 0:
            print('[shadow] listing all allocated non-current runs')
        else:
            print('[shadow] listing allocated non-current runs for size class %d' \
                    % (size_class))

        total_runs = len(jeheap.runs)
        print('[shadow] [total non-current runs %d]' % (total_runs))

        run_counter = 0

        for i in range(0, total_runs):
            if size_class == 0:
                print(jeheap.runs[i])
            else:
                if size_class == jeheap.runs[i].region_size:
                    print(jeheap.runs[i])
                    run_counter = run_counter + 1

        if size_class == 0:
            print('[shadow] [total non-current runs %d]' % (total_runs))
        else:
            print('[shadow] [total non-current runs for size class %d: %d]' \
                    % (size_class, run_counter))

def dump_bins(proc = none):
    '''Dump info on jemalloc bins'''

    global jeheap
    
    load_jeheap(proc)

    for i in range(0, len(jeheap.arenas)):
        print(jeheap.arenas[i])

        for j in range(0, len(jeheap.arenas[i].bins)):
            print(jeheap.arenas[i].bins[j])

def dump_regions(size_class, proc = none):
    '''Dump all current regions of the given size class'''

    global jeheap

    load_jeheap(proc)

    print('[shadow] dumping all regions of size class %d' % (size_class))
    found = false

    for i in range(0, len(jeheap.arenas)):
        for j in range(0, len(jeheap.arenas[i].bins)):

            if jeheap.arenas[i].bins[j].run.region_size == size_class:
                found = true
                print(jeheap.arenas[i].bins[j].run)
                    
                # XXX: the bitmask of small-sized runs is too big to display
                # print('[shadow] [regs_mask %s]' % \
                #       (jeheap.arenas[i].bins[j].run.regs_mask))

                for k in range(0, len(jeheap.arenas[i].bins[j].run.regions)):
                    print(jeheap.arenas[i].bins[j].run.regions[k])

    if found == false:
        print('[shadow] no regions found for size class %d' % (size_class))

def dump_run(addr, proc = none):
    '''Display the given run and its regions'''

    global jeheap

    load_jeheap(proc)
    total_runs = len(jeheap.runs)
    found = false

    print('[shadow] searching for run 0x%08x' % (addr))

    # search for the given run in non-current runs first
    for i in range(0, total_runs):
        if jeheap.runs[i].start == addr:
            found = true

            print(jeheap.runs[i])

            for j in range(0, len(jeheap.runs[i].regions)):
                print(jeheap.runs[i].regions[j])

            break

    if found == true:
        return

    # search for the given run in current runs
    for i in range(0, len(jeheap.arenas)):
        for j in range(0, len(jeheap.arenas[i].bins)):
            if jeheap.arenas[i].bins[j].run.start == addr:
                found = true

                print(jeheap.arenas[i].bins[j].run)

                for k in range(0, len(jeheap.arenas[i].bins[j].run.regions)):
                    print(jeheap.arenas[i].bins[j].run.regions[k])

                break

    if found == true:
        return

    print('[shadow] run 0x%08x not found' % (addr))

def dump_address(addr, proc = none):
    '''Display all available details for an address'''
    
    ainfo = find_address(addr, proc)
    print(ainfo)

def parse_nursery(proc = none):
    '''Parse the current SpiderMonkey's JSRuntime GC nursery'''

    global dbg_engine
    global nursery_heap

    lines = dbg.eval_expr(dbg.nursery_expr).split('\n')

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

def dump_nursery(proc = none):
    '''Display info on the current SpiderMonkey's JSRuntime GC nursery'''

    global nursery_heap

    parse_nursery()
    print(nursery_heap)

def pwnarray(addr, new_length = 0x666, proc = none):
    '''Modify the array's (ArrayObject) initlen, capacity and length in memory'''
    
    global dbg_engine

    if dbg_engine == 'pykd':
        # modify the ArrayObject's initial length
        dbg.execute('ed %x %x' % (addr + 0x4, new_length))

        # modify the ArrayObject's capacity
        dbg.execute('ed %x %x' % (addr + 0x8, new_length))

        # modify the ArrayObject's length
        dbg.execute('ed %x %x' % (addr + 0xc, new_length))

        lines = dbg.execute('dd %x l?8' % (addr)).split('\n')
        
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

def find_address(addr, proc = none):

    global jeheap

    addr_info = jemalloc.address_info()
    addr_info.addr = addr

    load_jeheap(proc)
    total_runs = len(jeheap.runs)

    # look in non-current runs first
    for i in range(0, total_runs):
        if (addr >= jeheap.runs[i].start) and (addr <= jeheap.runs[i].end):
            
            addr_info.parent_run = jeheap.runs[i]

            break

    # then in current runs
    if addr_info.parent_run == none:
        for i in range(0, len(jeheap.arenas)):
            for j in range(0, len(jeheap.arenas[i].bins)):
                if (addr >= jeheap.arenas[i].bins[j].run.start) and \
                        (addr <= jeheap.arenas[i].bins[j].run.end):
                    
                    addr_info.parent_run = jeheap.arenas[i].bins[j].run
                    addr_info.arena_addr = jeheap.arenas[i].addr
                    addr_info.current_run_flag = true

                    break

    # find if it belongs to a region
    if addr_info.parent_run != none:
        for i in range(0, len(addr_info.parent_run.regions)):
            if (addr >= addr_info.parent_run.regions[i].addr) and \
                    (addr < (addr_info.parent_run.regions[i].addr + \
                    addr_info.parent_run.region_size)):

                addr_info.parent_region = addr_info.parent_run.regions[i]

                break

    # find the chunk it belongs to
    for i in range(0, len(jeheap.chunks)):
        if (addr >= jeheap.chunks[i].addr) and \
                (addr < (jeheap.chunks[i].addr + jeheap.chunk_size)):

            addr_info.chunk_addr = jeheap.chunks[i].addr

            if addr_info.arena_addr == 0:
                addr_info.arena_addr = jeheap.chunks[i].arena_addr

            break

    return addr_info

def dump_symbol(size, has_vtable = false, from_mozjs = true, from_xul = false, from_dom = false):
    '''Display information on Firefox-specific symbols'''
    
    global xul_symbols_pickle

    dom_prefix = 'mozilla::dom::'
    js_prefix = 'js::'

    xul_symbols = []

    pfd = open(xul_symbols_pickle, 'rb')
    xul_symbols = pickle.load(pfd)
    pfd.close()

    if from_mozjs == true:
        if has_vtable == false:
            print('[shadow] searching for SpiderMonkey symbols of size %d' % (size))
        else:
            print('[shadow] searching for SpiderMonkey class symbols of size %d with vtable' \
                            % (size))

        for symbol in xul_symbols:
            if not symbol.name.startswith(js_prefix):
                continue

            if size == symbol.size:
                if has_vtable == true:
                    if symbol.kind == 'class' and symbol.has_vtable == true:
                        print('[shadow] %s' % (symbol))
                else:
                    print('[shadow] %s' % (symbol))

    if from_xul == true or from_dom == true:
        if has_vtable == false:
            if from_dom == true:
                print('[shadow] searching for DOM symbols of size %d' % (size))
            else:
                print('[shadow] searching for non-SpiderMonkey symbols of size %d' % (size))
        else:
            if from_dom == true:
                print('[shadow] searching for DOM class symbols of size %d with vtable' % (size))
            else:
                print('[shadow] searching for non-SpiderMonkey class symbols of size %d with vtable' \
                        % (size))

        for symbol in xul_symbols:
            if symbol.name.startswith(js_prefix):
                continue

            if size == symbol.size:
                if has_vtable == true:
                    if symbol.kind == 'class' and symbol.has_vtable == true:
                        if from_dom == true:
                            if symbol.name.startswith(dom_prefix):
                                print('[shadow] %s' % (symbol))
                        else:
                            print('[shadow] %s' % (symbol))
                else:
                    if from_dom == true:
                        if symbol.name.startswith(dom_prefix):
                            print('[shadow] %s' % (symbol))
                    else:
                        print('[shadow] %s' % (symbol))

def search(search_for, region_size = 0, search_current_runs = false, \
        quick_search = false, proc = none):
    '''Search the jemalloc heap for the given hex value'''

    global jeheap

    load_jeheap(proc)
    results = []

    if search_current_runs == true:
        if region_size == 0:
            print('[shadow] searching all current runs for %s' % (search_for))
        else:
            print('[shadow] searching all current runs of size class %d for %s' \
                    % (region_size, search_for))
    
        for i in range(0, len(jeheap.arenas)):
            for j in range(0, len(jeheap.arenas[i].bins)):
                try:
                    if region_size == 0:
                        results.extend(dbg.search(jeheap.arenas[i].bins[j].run.start, \
                                jeheap.arenas[i].bins[j].run.end, search_for))
                    else:
                        if jeheap.arenas[i].bins[j].run.region_size == region_size:
                            results.extend(dbg.search(jeheap.arenas[i].bins[j].run.start, \
                                jeheap.arenas[i].bins[j].run.end, search_for))
                except:
                    continue
    else:
        if region_size == 0:
            print('[shadow] searching all chunks for %s' % (search_for))

            for chunk in jeheap.chunks:
                try:
                    results.extend(dbg.search(chunk.addr, \
                            chunk.addr + jeheap.chunk_size, search_for))
                except:
                    continue
        else:
            print('[shadow] searching all non-current runs of size class %d for %s' \
                % (region_size, search_for))

            for i in range(0, len(jeheap.runs)):
                try:
                    if region_size == 0:
                        results.extend(dbg.search(jeheap.runs[i].start, \
                                jeheap.runs[i].end, search_for))
                    else:
                        if jeheap.runs[i].region_size == region_size:
                            results.extend(dbg.search(jeheap.runs[i].start, \
                                    jeheap.runs[i].end, search_for))
                except:
                    continue

    # display results

    if not results:
        print('[shadow] value %s not found' % (search_for))
        return

    for (where, start_addr) in results:
        if search_current_runs == true:

            ainfo = none

            if quick_search == false:
                ainfo = find_address(dbg.to_int(where))

            if (ainfo != none) and (ainfo.parent_run != none) and (ainfo.parent_region != none):

                print('[shadow] found %s at %s (run 0x%08x, region 0x%08x, region size %04d)' \
                        % (search_for, where, ainfo.parent_run.start, ainfo.parent_region.addr, \
                                    ainfo.parent_run.region_size))

            else:

                print('[shadow] found %s at %s (run 0x%08x)' % \
                        (search_for, where, start_addr))

        else:
            
            ainfo = none

            if quick_search == false:
                ainfo = find_address(dbg.to_int(where))

            if (ainfo != none) and (ainfo.parent_run != none) and (ainfo.parent_region != none):

                print('[shadow] found %s at %s (run 0x%08x, region 0x%08x, region size %04d)' \
                        % (search_for, where, ainfo.parent_run.start, ainfo.parent_region.addr, \
                                    ainfo.parent_run.region_size))

            else:

                print('[shadow] found %s at %s (chunk 0x%08x)' % \
                        (search_for, where, start_addr))

# EOF
