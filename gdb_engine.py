# shadow - De Mysteriis Dom jemalloc

import resource

try:
    import gdb
except ImportError:
    raise Exception('[shadow] gdb_engine is only usable from within gdb')


# cache
cache_dword_size = None
cache_page_size = None
cache_int_size = None
cache_offsets = {}
cache_values= {}
cache_sizes = {}


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


def buf_to_val(buf):
    val = 0

    for i in range(0, len(buf)):
        val |= (buf[i] << i * 8)

    return val


def get_page_size():
    global cache_page_size

    if not cache_page_size:
        cache_page_size = resource.getpagesize()

    return cache_page_size


def get_xul_version():
    return gdb.parse_and_eval('gToolkitVersion')


def get_arch_running():
    arch = gdb.selected_frame().architecture().name()

    if 'aarch64' == arch:
        return 'Aarch64'
    elif 'arm' in arch:
        return 'ARM'
    elif 'i386' == arch:
        return 'x86'
    elif 'x86-64' in arch:
        return 'x86-64'


def get_arch():
    # try to use GDB's architecture API first. If the program is not running
    # this will throw an exception but so will `execute("info proc start")`
    try:
        return get_arch_running()
    except gdb.error as e:
        pass

    # get the start of text
    text_addr = None
    for l in execute("info proc stat").split("\n"):
        if l.startswith("Start of text:"):
            text_addr = int(l.split(":")[1], 16)
            break

    # raise exception?
    if text_addr is None:
        return None

    e_machine = read_memory(text_addr + 0x12 , 2)

    if e_machine == 3:
        return "x86"
    if e_machine == 0x28:
        return "ARM"
    if e_machine == 0x3E:
        return "x86-64"
    if e_machine == 0xB7:
        return "Aarch64"

    # raise exception?
    return None


def get_dword_size():
    global cache_dword_size
    if not cache_dword_size:
        arch = get_arch()
        if arch in ["x86", "ARM"]:
            cache_dword_size = 4
        if arch in ["x86-64", "Aarch64"]:
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
        expr = '(size_t)&(((%s *)0)->%s) - (size_t)((%s *)0)' % \
               (struct_name, member_name, struct_name)

        cache_offsets[k] = to_int(gdb.parse_and_eval(expr))
    return cache_offsets[k]


def sizeof(type_name):
    global cache_sizes
    k = type_name
    if k not in cache_sizes:
        cache_sizes[k] = to_int(gdb.parse_and_eval('sizeof(%s)' % (type_name)))
    return cache_sizes[k]


def get_value(symbol, ignore_cache=False):
    global cache_values
    k = symbol
    # stripped libc gdb fix
    if symbol in ['arenas', 'je_arenas', 'chunk_rtree',
                  'g_thread_list', 'je_tcache_bin_info',
                  'tcache_bin_info']:
        # fuck gdb
        symbol = '*((unsigned long int *) &%s)' % symbol

    if ignore_cache:
        return gdb.parse_and_eval(symbol)

    if k not in cache_values:
        cache_values[k] = gdb.parse_and_eval(symbol)
    return cache_values[k]


def addressof(symbol):
    return get_value('&' + symbol)


def eval_expr(expr):
    return gdb.parse_and_eval(expr)


def execute(expr):
    return gdb.execute(expr, to_string = True)


def read_memory(addr, size):
    proc = gdb.selected_inferior()
    return buf_to_le(proc.read_memory(addr, size))


def read_bytes(addr, size):
    proc = gdb.selected_inferior()
    return bytearray(proc.read_memory(addr, size))


def read_bytearray(addr, size):
    proc = gdb.selected_inferior()
    return bytearray(proc.read_memory(addr, size))


# todo: check endianess
def read_dwords(addr, size):
    proc = gdb.selected_inferior()

    dword_size = get_dword_size()
    ndwords = size * dword_size

    bytearr = read_bytes(addr, ndwords)

    dwords = []
    for i in range(0, ndwords, dword_size):
        dword = bytearr[i]
        for j in range(1, dword_size):
            dword += bytearr[i+j] << j * 8
        dwords.append(dword)
    return dwords


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
        return val_bytes

    val = 0
    for i in range(0, size):
        val |= (val_bytes[i] << i * 8)

    return val


def search(start_addr, end_addr, dword):
    search_expr = 'find 0x%x, 0x%x, 0x%s'
    results = []

    if dword.startswith('0x'):
        dword = dword[len('0x'):]

    search_str = search_expr % (start_addr, end_addr, dword)
    out_str = gdb.execute(search_str, to_string = True)
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

    for ln in execute('info proc mappings').split('\n'):
        # [start, end, size, offset, objfile]
        l = ln.split()
        # skip if objfile is missing
        if len(l) < 4:
            continue

        # skip the first line
        if l[0] == 'Start':
            continue
        #todo: filter out [stack], [vsyscall], etc?
        if len(l) < 5:
            objfile = l[0]
        else:
            objfile = l[4]
            objfile = objfile.split("/")[-1]

        start = int(l[0], 16)
        end = int(l[1], 16)

        if objfile not in modules_dict:
            modules_dict[objfile] = [(start, end),]
        else:
            modules_dict[objfile].append((start, end))
    return modules_dict
