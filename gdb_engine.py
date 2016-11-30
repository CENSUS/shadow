# shadow - De Mysteriis Dom jemalloc

import sys
import resource

true = True
false = False
none = None

sys.path.append('.')

try:
    import gdb
except ImportError:
    print('[shadow] gdb_engine is only usable from within gdb')
    sys.exit()

address_separator = ':'

# gdb expressions for parsing arenas
arena_expr = 'arenas[%d]'
arena_reg_size_expr = 'arenas[%d].bins[%d].reg_size'
arena_reg0_offset_expr = 'arenas[%d].bins[%d].reg0_offset'
arena_bin_info_reg_size_expr = 'arena_bin_info[%d].reg_size'
arena_bin_info_nregs_expr = 'arena_bin_info[%d].nregs'
arena_bin_info_run_size_expr = 'arena_bin_info[%d].run_size'
arena_runcur_expr = 'arenas[%d].bins[%d].runcur'
arena_bin_addr_expr = '&arenas[%d].bins[%d]'

# gdb expressions for parsing all runs and their regions
chunk_map_expr = 'x/%d%sx ((arena_chunk_t *)%#x)->map'

# gdb expressions for parsing current runs
regs_mask_expr = 'x/%dbt arenas[%d].bins[%d].runcur.regs_mask'
regs_mask_addr_expr = 'x/x ((arena_run_t *)%#x)->regs_mask'
regs_mask_addr_bits_expr = 'x/%dbt %#x'

# gdb expressions for parsing chunks
chunk_rtree_root_expr = 'chunk_rtree.root'
chunk_rtree_height_expr = 'chunk_rtree.height'
chunk_rtree_level2bits_expr = 'chunk_rtree.level2bits[%d]'
chunk_radix_expr = 'x/%d%sx %#x'
chunk_arena_expr = '((arena_chunk_t *)%#x)->arena'

def to_int(val):
    sval = str(val)
    start = sval.find('0x')

    if start != -1:
        end = sval.find(':')

        if end == -1:
            end = sval.find('\n')

            if end == -1:
                return int(sval[start:], 16)
            else:
                return int(sval[start:end], 16)
        else:
            return int(sval[start:end], 16)

    elif sval.startswith('unsigned int'):
        return int(sval[len('unsigned int'):])
    else:
        return int(sval)

def buf_to_le(buf):
    # this function is from seanhn's tcmalloc_gdb
    tmp = 0

    for i in range(0, len(buf)):
        tmp |= (ord(buf[i]) << i * 8)

    return tmp

def get_page_size():
    return resource.getpagesize()

def get_xul_version():
    return gdb.parse_and_eval('gToolkitVersion')

def get_arch():
    # XXX
    return 'x86'

def offsetof(struct_name, member_name):
    expr = '(size_t)&(((%s *)0)->%s) - (size_t)((%s *)0)' % \
        (struct_name, member_name, struct_name)
        
    return to_int(gdb.parse_and_eval(expr))

def sizeof(type_name):
    return to_int(gdb.parse_and_eval('sizeof(%s)' % (type_name)))

def get_value(symbol):
    return gdb.parse_and_eval(symbol)

def eval_expr(expr):
    return gdb.parse_and_eval(expr)

def execute(expr):
    return gdb.execute(expr, to_string = true)

def read_memory(addr, size, proc):
    return buf_to_le(proc.read_memory(addr, size))

def search(start_addr, end_addr, dword):
    search_expr = 'find 0x%x, 0x%x, 0x%s'
    results = []

    if dword.startswith('0x'):
        dword = dword[len('0x'):]

    search_str = search_expr % (start_addr, end_addr, dword)
    out_str = gdb.execute(search_str, to_string = true)
    str_results = out_str.split('\n')

    for str_result in str_results:
        if str_result.startswith('0x'):
            results.append((str_result, start_addr))

    return results

# EOF
