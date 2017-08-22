# shadow - De Mysteriis Dom jemalloc

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

# cache
cache_dword_size = None
cache_int_size = None
cache_page_size = None
cache_offsets = {}
cache_values= {}
cache_sizes = {}


# XXX: this function is getting complicated; needs to be re-written with
#      pykd's typed memory access features
def to_int(val):
    sval = str(val)
    start = sval.find('0x')
    if start != -1:
        end = sval.find('\n')
        if end == -1:
            return int(sval[start:].replace('`', ''), 16)
        else:
            return int(sval[start:end].replace('`', ''), 16)

    elif sval.startswith('unsigned int'):
        if sval.startswith('unsigned int64'):
            return int(sval[len('unsigned int64'):])
        else:
            return int(sval[len('unsigned int'):])
    else:
        return int(sval.replace('`', ''))


def buf_to_le(buf):
    # this function is from seanhn's tcmalloc_gdb
    tmp = 0
    for i in range(0, len(buf)):
        tmp |= (buf[i] << i * 8)
    return tmp


def get_page_size():
    global cache_page_size
    if not cache_page_size:
        cache_page_size = pykd.pageSize()
    return cache_page_size


def get_xul_version():
    version = pykd.loadCStr(pykd.module('xul').offset('gToolkitVersion'))
    return version


def get_arch():
    if pykd.is64bitSystem():
        return 'x86-64'
    return 'x86'

def get_dword_size():
    global cache_dword_size
    if not cache_dword_size:
        arch = get_arch()
        if arch == 'x86':
            cache_dword_size = 4
        if arch == 'x86-64':
            cache_dword_size = 8
    return cache_dword_size


def int_size():
    global cache_int_size
    if not cache_int_size:
        cache_int_size = 4
    return cache_int_size


def offsetof(struct_name, member_name):
    global cache_offsets
    k = struct_name + "." + member_name
    if k not in cache_offsets:
        # speed up
        s = 'mozglue!' + struct_name
        cache_offsets[k] = pykd.typeInfo(s).fieldOffset(member_name)
    return cache_offsets[k]


def sizeof(type_name):
    global cache_sizes
    k = type_name
    if k not in cache_sizes:
        type_name = 'mozglue!' + type_name # speedup
        cache_sizes[k] = pykd.typeInfo(type_name).size()
    return cache_sizes[k]


def get_value(symbol):
    global cache_values
    k = symbol
    if k not in cache_values:
        mozglue = pykd.module('mozglue')
        symbol_addr = mozglue.offset(symbol)
        cache_values[k] = pykd.ptrDWord(symbol_addr)
    return cache_values[k]


def addressof(symbol):
    mozglue = pykd.module('mozglue')
    return mozglue.offset(symbol)


def eval_expr(expr):
    sval = pykd.dbgCommand('?? %s' % (expr))
    return sval


def execute(expr):
    sval = pykd.dbgCommand(expr)
    return sval


def read_memory(addr, size):
    return buf_to_le(pykd.loadBytes(addr, size))

# xxx
def read_bytes(addr, size):
    try:
        return bytearray(pykd.loadBytes(addr, size))
    except:
        b = []
        off = 0
        while len(b) < size:
            try:
                b += pykd.loadBytes(addr + off, 0x1000)
            except:
                b += [0] * 0x1000
            off += 0x1000
        return b


def read_dwords(addr, size):
    if get_dword_size() == 4:
        return pykd.loadDWords(addr, size)
    else:
        return pykd.loadQWords(addr, size)


def read_dword(addr):
    return read_dwords(addr, 1)[0]


def dword_from_buf(buf, off):
    dword = 0

    for i in range(0, get_dword_size()):
        dword |= buf[off+i] << i * 8

    return dword


def int_from_buf(buf, off):
    dword = 0

    for i in range(0, int_size()):
        dword |= buf[off+i] << i * 8

    return dword


def read_struct_member(buf, struct_name, member_name, size):
    off = offsetof(struct_name, member_name)
    val_bytes = buf[off:off+size]

    if size > get_dword_size():
        return val

    val = 0
    for i in range(0, size):
        val |= (val_bytes[i] << i * 8)

    return val


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


def modules_dict():
    """
    modules_dict[objfile] = (start, end)
    """
    modules_dict = {}
    for module in pykd.getModulesList():
        objfile = module.name()
        start = module.begin()
        end = module.end()

        if objfile not in modules_dict:
            modules_dict[objfile] = [(start, end),]
        else:
            modules_dict[objfile].append((start, end))
    return modules_dict
# EOF
