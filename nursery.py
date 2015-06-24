# shadow - De Mysteriis Dom Firefox

import sys
import warnings

sys.path.append('.')

true = True
false = False
none = None

class nursery:

    def __init__(self, jsruntime_addr = 0, start_addr = 0, end_addr = 0, \
            next_free_addr = 0):

        self.jsruntime_addr = jsruntime_addr    # runtime_
        self.start_addr = start_addr            # heapStart_
        self.end_addr = end_addr                # heapEnd_
        self.size = end_addr - start_addr       # heapEnd_ - heapStart_
        self.next_free_addr = next_free_addr    # position_

    def __str__(self):

        return '[shadow] [nursery 0x%08x (runtime 0x%08x)] [size 0x%08x]' \
                ' [next free address 0x%08x]' % (self.start_addr, \
                self.jsruntime_addr, self.size, self.next_free_addr)

# unit testing
if __name__ == '__main__':
    print('[shadow] unit testing not implemented yet')
    sys.exit()

# EOF
