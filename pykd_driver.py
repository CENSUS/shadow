# shadow - De Mysteriis Dom Firefox

import os
import sys
import getopt
import warnings

sys.path.append('.')

import shadow
import pykd_engine as dbg

true = True
false = False
none = None

if __name__ == '__main__':
    argc = len(sys.argv)

    # don't remove this (still required?)
    tmp = shadow.pykd.dbgCommand('?? mozglue!arenas[0]')

    if argc == 1:
        shadow.help()
        sys.exit()

    if sys.argv[1] == 'help':
        shadow.help()

    elif sys.argv[1] == 'jeparse':
        shadow.parse()

    elif sys.argv[1] == 'version':
        shadow.version()
        shadow.firefox_version()

    elif sys.argv[1] == 'jedump':
        arg = ''

        try:
            arg = sys.argv[2]
            screen = false
        except:
            screen = true

        shadow.dump_all(filename = arg, dump_to_screen = screen)

    elif sys.argv[1] == 'jechunks':
        shadow.dump_chunks()

    elif sys.argv[1] == 'jearenas':
        shadow.dump_arenas()

    elif sys.argv[1] == 'jeruns':
        current_runs = false
        size = 0
        
        try:
    
            alist, args = getopt.getopt(sys.argv[2:], 'cs:')

            for (field, val) in alist:

                if field in '-c':
                    current_runs = true

                if field in '-s':
                    size = int(val)

        except:
            
            print('[shadow] usage: jeruns [-cs]')
            print('[shadow] options:')
            print('[shadow]    -c           display current runs only')
            print('[shadow]    -s <size>    runs of the given size class only')
            print('[shadow] for example: jeruns -s 256 ')
            sys.exit()

        shadow.dump_runs(dump_current_runs = current_runs, size_class = size)

    elif sys.argv[1] == 'jebins':
        shadow.dump_bins()

    elif sys.argv[1] == 'nursery':
        shadow.dump_nursery()

    elif sys.argv[1] == 'jeregions':
        size_class = 0

        try:
            size_class = int(sys.argv[2])
        except:
            print('[shadow] usage: jeregions <size class>')
            print('[shadow] for example: jeregions 1024')
            sys.exit()

        shadow.dump_regions(size_class)
    
    elif sys.argv[1] == 'pa':
        addr = 0
        new_len = 0x666

        try:
            if sys.argv[2].startswith('0x'):
                addr = dbg.to_int(sys.argv[2])
                new_len = dbg.to_int(sys.argv[3])
            else:
                addr = dbg.to_int('0x%s' % (sys.argv[2]))
                new_len = dbg.to_int(sys.argv[3])
        except:
            if addr != 0:
                shadow.pwnarray(addr)
                sys.exit()
            else:
                print('[shadow] usage: pa <address> [<new length>]')
                print('[shadow] for example: pa 0x13f1fc00 0x1000')
                sys.exit()

        shadow.pwnarray(addr, new_length = new_len)

    elif sys.argv[1] == 'jeinfo':
        addr = 0

        try:
            if sys.argv[2].startswith('0x'):
                addr = dbg.to_int(sys.argv[2])
            else:
                addr = dbg.to_int('0x%s' % (sys.argv[2]))
        except:
            print('[shadow] usage: jeinfo <address>')
            print('[shadow] for example: jeinfo 0x079e5440')
            sys.exit()

        shadow.dump_address(addr)

    elif sys.argv[1] == 'jerun':
        addr = 0

        try:
            if sys.argv[2].startswith('0x'):
                addr = dbg.to_int(sys.argv[2])
            else:
                addr = dbg.to_int('0x%s' % (sys.argv[2]))
        except:
            print('[shadow] usage: jerun <address>')
            print('[shadow] for example: jeinfo 0x087e1000')
            sys.exit()

        shadow.dump_run(addr)

    elif sys.argv[1] == 'symbol':
        size = 0
        vtable = false
        mozjs = false
        xul = false
        dom = false

        try:

            alist, args = getopt.getopt(sys.argv[2:], 'vjdx')

            for (field, val) in alist:

                if field in '-v':
                    vtable = true

                if field in '-j':
                    mozjs = true

                if field in '-d':
                    dom = true

                if field in '-x':
                    xul = true

            size = int(args[0])

            if mozjs == dom == xul == false:
                raise Exception()

        except:

            print('[shadow] usage: symbol [-vjdx] <size>')
            print('[shadow] options:')
            print('[shadow]    -v  only class symbols with vtable')
            print('[shadow]    -j  only symbols from SpiderMonkey')
            print('[shadow]    -d  only DOM symbols')
            print('[shadow]    -x  only non-SpiderMonkey symbols')
            sys.exit()

        shadow.dump_symbol(size, has_vtable = vtable, from_mozjs = mozjs, \
                from_xul = xul, from_dom = dom)

    elif sys.argv[1] == 'jesearch':
        search_for = ''
        current_runs = false
        quick = false
        size_class = 0

        try:

            alist, args = getopt.getopt(sys.argv[2:], 'cs:q')

            for (field, val) in alist:
                
                if field in '-c':
                    current_runs = true

                if field in '-s':
                    size_class = int(val)
                    
                if field in '-q':
                    quick = true

            search_for = args[0]

        except:

            print('[shadow] usage: jesearch [-cqs] <hex dword>')
            print('[shadow] options:')
            print('[shadow]    -c           search current runs only')
            print('[shadow]    -q           quick search')
            print('[shadow]    -s <size>    regions of the given size only')
            print('[shadow] for example: jesearch -c -s 256 0x41424344')
            sys.exit()

        shadow.search(search_for, region_size = size_class, \
                search_current_runs = current_runs, quick_search = quick)

    sys.exit()

# EOF
