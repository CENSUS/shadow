# shadow - De Mysteriis Dom Firefox

import sys

true = True
false = False
none = None

sys.path.append('.')

try:
    import pykd
except ImportError:
    print('[shadow] pykd_engine is only usable from within windbg/pykd')
    sys.exit()

address_separator = '  '

# windbg expressions for parsing arenas
arena_expr = 'mozglue!arenas[%d]'
arena_reg_size_expr = 'mozglue!arenas[%d]->bins[%d].reg_size'
arena_reg0_offset_expr = 'mozglue!arenas[%d]->bins[%d].reg0_offset'
arena_runcur_expr = 'mozglue!arenas[%d]->bins[%d].runcur'
arena_bin_addr_expr = '&mozglue!arenas[%d]->bins[%d]'

# windbg expressions for parsing all runs and their regions
chunk_map_expr = '((mozglue!arena_chunk_t *)0x%x)->map'
chunk_map_dump_expr = 'dp %x L%d'

# windbg expressions for parsing current runs
regs_mask_expr = 'dyb /c1 mozglue!arenas[%d]->bins[%d].runcur.regs_mask L%d'
regs_mask_addr_expr = '((mozglue!arena_run_t *)0x%x)->regs_mask'
regs_mask_addr_bits_expr = 'dyb /c1 0x%x L%d'

# windbg expressions for parsing chunks
chunk_rtree_root_expr = 'mozglue!chunk_rtree->root'
chunk_rtree_height_expr = 'mozglue!chunk_rtree->height'
chunk_rtree_level2bits_expr = 'mozglue!chunk_rtree->level2bits[%d]'
chunk_radix_expr = 'dp %x L%d'
chunk_arena_expr = '((mozglue!arena_chunk_t *)0x%x)->arena'

# windbg expressions for parsing nursery data
nursery_expr = 'xul!nsXPConnect::gSelf->mRuntime->mJSRuntime->gc.nursery'

def to_int(val):
    sval = str(val)
    start = sval.find('0x')
    
    if start != -1:
        end = sval.find('\n')
        
        if end == -1:
            return int(sval[start:], 16)
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
        tmp |= (buf[i] << i * 8)

    return tmp

def get_page_size():
    return pykd.pageSize()

def get_xul_version():
    version = pykd.loadCStr(pykd.module('xul').offset('gToolkitVersion'))
    return version

def get_arch():
    if pykd.is64bitSystem():
        return 'x86-64'

    return 'x86'

def offsetof(struct_name, member_name):
    return pykd.typeInfo(struct_name).fieldOffset(member_name)

def sizeof(type_name):
    return to_int(pykd.dbgCommand('?? sizeof(%s)' % (type_name)))

def get_value(symbol):
    mozglue = pykd.module('mozglue')
    symbol_addr = mozglue.offset(symbol)
    return pykd.ptrDWord(symbol_addr)

def eval_expr(expr):
    sval = pykd.dbgCommand('?? %s' % (expr))
    return sval

def execute(expr):
    sval = pykd.dbgCommand(expr)
    return sval

def read_memory(addr, size, proc = none):
    return buf_to_le(pykd.loadBytes(addr, size))

def search(start_addr, end_addr, dword):
    search_expr = 's -[1]d %x %x %s'
    results = []

    search_str = search_expr % (start_addr, end_addr, dword)
    out_str = pykd.dbgCommand(search_str)
    str_results = out_str.split('\n')

    for str_result in str_results:
        if str_result.startswith('0x'):
            results.append((str_result, start_addr))

    return results

# EOF
