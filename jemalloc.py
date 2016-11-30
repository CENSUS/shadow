# shadow - De Mysteriis Dom jemalloc

import sys
import warnings
import platform

sys.path.append('.')

true = True
false = False
none = None

INT_SIZE = 4 # on all tested platforms

def get_dword_size():
    # ugly but portable
    (arch, exe) = platform.architecture()

    if arch.startswith('64'):
        return 8
    else:
        return 4

class jemalloc:

    def __init__(self, chunks = [], chunk_size = 0, \
        arenas = [], narenas = 0, runs = [], nbins = 0, \
        magrack_size = 0, magaz_flag = false, \
        standalone_flag = false):

        self.chunks = chunks
        self.chunk_size = chunk_size
        self.arenas = arenas
        self.narenas = narenas
        self.nbins = nbins
        self.ntbins = 0
        self.nsbins = 0
        self.nqbins = 0
        self.magrack_size = magrack_size
        self.DWORD_SIZE = get_dword_size()
        self.runs = runs

        self.MAGAZINES = magaz_flag
        self.STANDALONE = standalone_flag

    def __str__(self):

        if self.MAGAZINES == false:
            return '[shadow] [jemalloc] [arenas %02d] [bins %02d]' \
                   ' [runs %02d]' % (self.narenas, self.nbins, len(self.runs))
        else:
            return '[shadow] [jemalloc] [arenas %02d] [bins %02d] ' \
                   '[runs %02d] [magazine rack/tcache size %04d]' % \
                    (self.narenas, self.nbins, len(self.runs), self.magrack_size)

class arena_chunk:

    def __init__(self, addr = 0, arena_addr = 0):

        self.addr = addr
        self.arena_addr = arena_addr

    def __str__(self):

        if self.arena_addr != 0:
            return '[shadow] [chunk 0x%08x] [arena 0x%08x]' % \
                    (self.addr, self.arena_addr)
        else:
            return '[shadow] [chunk 0x%08x] [orphan]' % (self.addr)

class arena_run:

    def __init__(self, start = 0, end = 0, size = 0, bin_addr = 0, \
        region_size = 0, reg0_offset = 0, total_regions = 0, \
        free_regions = 0, regions = []):
        
        self.start = start
        self.end = end
        self.size = size
        self.bin_addr = bin_addr
        self.region_size = region_size
        self.reg0_offset = reg0_offset
        self.total_regions = total_regions
        self.free_regions = free_regions
        self.regions = regions
        self.regs_mask = ''

    def __str__(self):

        return '[shadow] [run 0x%08x] [size %06d] [bin 0x%08x] [region size %04d] ' \
               '[total regions %04d] [free regions %04d]' % \
                (self.start, self.size, self.bin_addr, \
                 self.region_size, self.total_regions, self.free_regions)

class arena_bin:

    def __init__(self, addr = 0, index = 0, runcur = none):

        self.addr = addr
        self.index = index
        self.run = runcur

    def __str__(self):

        return '[shadow] [bin %02d (0x%08x)] [size class %04d] [runcur 0x%08x]' % \
            (self.index, self.addr, self.run.region_size, self.run.start)

class region:

    def __init__(self, index = 0, addr = 0, is_free = 1):

        self.index = index
        self.addr = addr
        self.is_free = is_free
        self.content_preview = ''

    def __str__(self):

        str = '[shadow] [region %03d]' % (self.index)

        if self.is_free == 1:
            str += ' [free]'
        elif self.is_free == 0:
            str += ' [used]'

        if self.content_preview != '':
            str += ' [0x%08x] [%s]' % (self.addr, self.content_preview)
        else:
            str += ' [0x%08x]' % (self.addr)

        return str

class arena:

    def __init__(self, addr = 0, index = 0, bins = []):
        
        self.addr = addr
        self.index = index
        self.bins = bins

    def __str__(self):
        
        return '[shadow] [arena %02d (0x%08x)] [bins %02d]' % \
            (self.index, self.addr, len(self.bins))

class address_info:

    def __init__(self, addr = 0, arena_addr = 0, parent_run = none, \
            current_run_flag = false, parent_region = none, chunk_addr = 0):

        self.addr = addr
        self.arena_addr = arena_addr
        self.parent_run = parent_run
        self.current_run_flag = current_run_flag
        self.parent_region = parent_region
        self.chunk_addr = chunk_addr

    def __str__(self):

        str = ''
        found = false

        if self.addr != 0:
            str += '[shadow] address 0x%08x\n' % (self.addr)

        if self.arena_addr != 0:
            str += '[shadow] parent arena 0x%08x\n' % (self.arena_addr)
            found = true

        if self.chunk_addr != 0:
            str += '[shadow] parent chunk 0x%08x\n' % (self.chunk_addr)
            found = true

        if self.parent_run:
            str += '[shadow] parent run 0x%08x\n' % (self.parent_run.start)
            found = true

        if self.current_run_flag == true:
            str += '[shadow] run 0x%08x is the current run of bin 0x%08x\n' \
                    % (self.parent_run.start, self.parent_run.bin_addr)

            found = true

        if self.parent_region:
            str += '[shadow] address 0x%08x belongs to region 0x%08x' \
                    % (self.addr, self.parent_region.addr)

            str += ' (size class %04d)\n' % (self.parent_run.region_size)
            str += '%s\n' % (self.parent_run.__str__())
            str += self.parent_region.__str__()

            found = true
        
        if found == false:
            str = '[shadow] address 0x%08x not found in the jemalloc-managed heap' % (self.addr)

        return str

# unit testing
if __name__ == '__main__':
    print('[shadow] unit testing not implemented yet')
    sys.exit()

# EOF
