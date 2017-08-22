# shadow - De Mysteriis Dom jemalloc

# This is an example of using shadow as a library.

import os
import sys
import getopt
import warnings

sys.path.insert(1, os.path.join(sys.path[0], '..'))
import shadow
import pykd_engine as dbg

true = True
false = False
none = None

def main():
    shadow.parse_nursery()
    # print('[*] nursery at: 0x%08x' % (shadow.nursery_heap.start_addr))
    fd = open('spray-reliability-nursery.txt', 'a')
    fd.write('0x%08x\n' % (shadow.nursery_heap.start_addr))
    fd.close()

    lines = dbg.execute('s 0x0 l?0xffffffff 00 00 00 00 1e 00 00 00 1e 00 00 00 1e 00 00 00')
    lines = lines.split('\n')

    fd = open('spray-reliability.txt', 'a')

    for line in lines:
        end = line.find(' ')

        if end == -1:
            break

        addr = line[:end]
        addrinfo = shadow.find_address(dbg.to_int('0x%s' % (addr)))

        if addrinfo.parent_region:
            # print('0x%08x' % (addrinfo.addr))
            fd.write('0x%08x\n' % (addrinfo.addr))

    fd.close()

if __name__ == '__main__':
    main()

# EOF
