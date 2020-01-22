# shadow - De Mysteriis Dom jemalloc

class jemalloc:
    def __init__(self, path=None):
        # memory organization
        self.chunk_size = None
        self.chunks = []
        self.runs = {}

        # memory management
        self.nbins = None
        self.narenas = None
        self.arenas = []
        self.tcaches = {}

        # small class size information
        self.bin_info = []
        self.tbin_info = []

        # modules loaded in process
        self.modules_dict = {}

        # misc information
        self.dword_size = None
        self.standalone = None

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


# small size class information
class bin_info:
        def __init__(self, reg_size, run_size, reg0_off, nregs):
            self.reg_size = reg_size
            self.run_size = run_size
            self.reg0_off = reg0_off
            self.nregs = nregs


class tbin_info:
    def __init__(self, ncached_max):
        self.ncached_max = ncached_max


# memory organization structs
class chunk:
    def __init__(self, addr, arena_addr, runs):
        self.addr = addr
        self.arena_addr = arena_addr
        self.runs = runs


class run:
    def __init__(self, hdr_addr, addr, size, binind,
                 nfree, regs_mask, regions):
        self.hdr_addr = hdr_addr
        self.addr = addr
        self.size = size
        self.binind = binind
        self.nfree = nfree
        self.regs_mask = regs_mask # v2 name
        self.bitmap = regs_mask    # v3 name
        self.regions = regions
        self.unallocated = False


class region:
    def __init__(self, index, addr, size, is_free, data, data_map):
        self.index = index
        self.addr = addr
        self.size = size
        self.is_free = is_free
        self.data = data
        self.data_map = data_map


# backend allocator structs
class arena:
    def __init__(self, addr, index, bins, chunks, tids):
        self.addr = addr
        self.index = index
        self.bins = bins
        self.chunks = chunks
        self.tids = tids


class arena_bin:
    def __init__(self, addr, index, runcur):
        self.addr = addr
        self.index = index
        self.runcur = runcur


# thread cache structs
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


# address info struct
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
