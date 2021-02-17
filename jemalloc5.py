# shadow - De Mysteriis Dom jemalloc

from dbg import dbg

class jemalloc:
    def __init__(self, path=None):
        # memory organization
        self.chunk_size = None
        self.chunks = []
        self.runs = {}
        self.extents = {}

        # memory management
        self.nbins = None
        self.narenas = None
        self.arenas = []
        self.arenas_addr = []
        self.tcaches = {}

        # all size classes
        self.nsizes = None
        self.sz_index2size_tab = []

        # small class size information
        self.bin_info = []
        self.tbin_info = []

        # modules loaded in process
        self.modules_dict = {}

        # misc information
        self.dword_size = None
        self.standalone = None
        self.version = None # This field is valid only when standalone is true

        # construct from snapshot
        if path:
            try:
                from pyrsistence import EMList, EMDict
            except ImportError:
                raise Exception("pyrsistence is needed for heap snapshots")

            self.chunks = EMList("%s/chunks" % path)
            self.runs = EMDict("%s/runs" % path)
            self.arenas = EMList("%s/arenas" % path)
            self.tcaches = EMList("%s/tcaches" % path)
            self.bin_info = EMList("%s/bin_info" % path)
            self.modules_dict = EMDict("%s/modules_dict" % path)

            try:
                import ConfigParser
            except ImportError:
                import configparser as ConfigParser

            config = ConfigParser.RawConfigParser()
            config.read("%s/jeheap.txt" % path)
            if config.has_section("jeheap"):
                d = {}
                for k,v in config.items("jeheap"):
                    d[k] = v

                if d["standalone"] == "True":
                    self.standalone = True
                else:
                    self.standalone = False

                    self.dword_size = int(d["dword_size"], 16)
                    self.narenas = int(d["narenas"], 16)
                    self.nbins = int(d["nbins"], 16)
                    self.chunk_size = int(d["chunk_size"], 16)
            else:
                raise Exception("Invalid jeheap.txt file")


class bin_info:
    '''
    A bin_info_t object. This replaced arena_bin_info_t from jemalloc 4.
    '''
    def __init__(self, data, struct_name):
        assert struct_name == 'bin_info_t'

        int_size = dbg.int_size()
        dword_size = dbg.get_dword_size()

        self.reg_size = dbg.read_struct_member(data, struct_name,
                                               "reg_size", dword_size)
        self.nregs = dbg.read_struct_member(data, struct_name,
                                            "nregs", int_size)
        self.slab_size = dbg.read_struct_member(data, struct_name,
                                               "slab_size", dword_size)


class tbin_info:
    def __init__(self, ncached_max):
        self.ncached_max = ncached_max


class extent:
    '''
    Representation of an extent_t object
    '''
    def __init__(self, addr, e_bits, e_addr, e_size_esn,
                 qre_next, qre_prev,
                 phn_prev, phn_next, phn_lchild):
        self.addr = addr
        self.e_addr = e_addr
        self.e_bits = e_bits
        # The next two fields are stored in a union
        self.e_size_esn = e_size_esn
        self.e_bsize = e_size_esn
        self.qre_next = qre_next
        self.qre_prev = qre_prev
        self.phn_prev = phn_prev
        self.phn_next = phn_next
        self.phn_lchild = phn_lchild

    def arena_ind(self):
        return self.e_bits & 0xfff

    def is_slab(self):
        return (self.e_bits & 0x1000) == 0x1000

    def nfree(self):
        return (self.e_bits & 0xffc000000) >> 26

    # Usable size class index
    def szind(self):
        return (self.e_bits & 0x3fc0000) >> 18

    def size(self):
        return self.e_size_esn >> 12

    def esn(self):
        return self.e_size_esn & 0xfff


def parse_extent(addr):
    dword_size = dbg.get_dword_size()
    mem = dbg.read_bytes(addr, dbg.sizeof('extent_t'))

    e_bits = dbg.read_struct_member(mem, 'extent_t', 'e_bits', 8)
    e_addr = dbg.read_struct_member(mem, 'extent_t', 'e_addr', dword_size)
    e_size_esn = dbg.read_struct_member(mem, 'extent_t', 'e_bsize', dword_size)

    # This code attempts to read the members of two anonymous structs. It will
    # break if any change happens to these structs.
    link_off = dbg.offsetof('extent_t', 'ql_link')
    qre_next   = dbg.dword_from_buf(mem, link_off)
    qre_prev   = dbg.dword_from_buf(mem, link_off + 1 * dword_size)
    phn_prev   = dbg.dword_from_buf(mem, link_off + 2 * dword_size)
    phn_next   = dbg.dword_from_buf(mem, link_off + 3 * dword_size)
    phn_lchild = dbg.dword_from_buf(mem, link_off + 4 * dword_size)

    return extent(addr, e_bits, e_addr, e_size_esn, qre_prev, qre_next,
                  phn_prev, phn_next, phn_lchild)


class arena:
    '''
    Representation of an arena_t object
    '''
    def __init__(self, addr, index, large, bins, tids):
        self.addr = addr
        self.index = index
        self.large = large
        self.bins = bins
        self.tids = tids

def parse_arena(jeheap, addr, index, nbins):

    # Parse pointer to head of large extents list
    large = dbg.read_dword(addr + dbg.offsetof('arena_t', 'large'))

    # Parse bins
    bin_size = dbg.sizeof('bin_t')

    bins_addr = addr + dbg.offsetof('arena_t', 'bins')
    bins_mem = dbg.read_bytes(bins_addr, nbins * bin_size)
    bins_mem = [bins_mem[z:z+bin_size]
                for z in range(0, nbins * bin_size, bin_size)]

    bins = [parse_bin(bins_addr + bin_size*i, i, bins_mem[i])
                for i in range(0, nbins)]

    return arena(addr, index, large, bins, [])


class bin:
    '''
    Representation of a bin_t object
    '''
    def __init__(self, addr, index, slabcur, slabs_nonfull, slabs_full):
        self.addr = addr
        self.index = index
        self.slabcur = slabcur
        self.slabs_nonfull = slabs_nonfull
        self.slabs_full = slabs_full

    def current(self):
        return self.slabcur


def parse_bin(address, index, data):

    dword_size = dbg.get_dword_size()

    slabcur = dbg.read_struct_member(data, 'bin_t', 'slabcur', dword_size)
    slabs_nonfull = dbg.read_struct_member(data, 'bin_t', 'slabs_nonfull',
                                           dword_size)
    slabs_full = dbg.read_struct_member(data, 'bin_t', 'slabs_full', dword_size)

    return bin(address, index, slabcur, slabs_nonfull, slabs_full)


class tcache:
    def __init__(self, addr, tid, tbins):
        self.addr = addr
        self.tid = tid
        self.tbins = tbins


class tcache_bin:
    def __init__(self, addr, index, low_water, lg_fill_div, ncached, avail, stack):
        self.addr = addr
        self.index = index
        self.low_water = low_water
        self.lg_fill_div = lg_fill_div
        self.ncached = ncached
        self.avail = avail
        # stack representation, initialized in shadow.parse_tcache()
        self.stack = stack


class address_info:
    def __init__(self):
        self.addr = None
        # heap
        self.chunk = None
        self.run = None
        self.region = None
        self.tcache = None
        # module
        self.module = None
        self.module_off = None
