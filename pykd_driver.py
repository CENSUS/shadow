# shadow - De Mysteriis Dom jemalloc

import os
import sys
import getopt
import warnings

sys.path.append('.')

import shadow
import pykd_engine as dbg


if __name__ == '__main__':
    argc = len(sys.argv)

    if argc == 1:
        shadow.help()
        sys.exit()

    if sys.argv[1] == 'jehelp':
        shadow.help()

    elif sys.argv[1] == 'jeparse':
        arg = sys.argv[2:]
        read_content_preview = False
        do_debug_log = False
        config_path = None

        for i in range(len(arg)):
            if arg[i] == "-r":
                read_content_preview = True
            if arg[i] == "-v":
                do_debug_log = True

            elif arg[i] == "-c":
                if i + 1 >= len(arg):
                    print('[shadow] empty configuration path')
                    sys.exit()
                config_path = arg[i+1]

        shadow.parse(read_content_preview, config_path, do_debug_log=do_debug_log)

    elif sys.argv[1] == 'jeversion':
        shadow.version()
        shadow.firefox_version()

    elif sys.argv[1] == 'jedump':
        arg = sys.argv[2:]

        if len(arg) == 0:
            path = None
        else:
            path = arg[0]

        shadow.dump_all(path=path)

    elif sys.argv[1] == 'jechunks':
        shadow.dump_chunks()

    elif sys.argv[1] == 'jechunk':
        arg = sys.argv[2:]
        if len(arg) >= 1:
            addr = arg[0]
        else:
            print('[shadow] usage: jechunk <address>')
            print('[shadow] for example: jechunk 0x900000')
            sys.exit(1)

        if addr.startswith('0x'):
            addr = dbg.to_int(addr)
        else:
            addr = dbg.to_int('0x%s' % (addr))
        shadow.dump_chunk(addr)

    elif sys.argv[1] == 'jearenas':
        shadow.dump_arenas()

    elif sys.argv[1] == 'jeruns':
        current_runs = False
        size = 0

        try:

            alist, args = getopt.getopt(sys.argv[2:], 'cs:')

            for (field, val) in alist:

                if field in '-c':
                    current_runs = True

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
        arg = sys.argv[2:]

        if len(arg) >= 2 and arg[0] == '-m':
            view_maps = True
            addr = arg[1]
        elif len(arg) == 1:
            view_maps = False
            addr = arg[0]
        else:
            print('[shadow] usage: jerun <address>')
            print('[shadow] usage: jerun -m <address>')
            print('[shadow] for example: jerun 0x087e1000')
            sys.exit()

        try:
            if addr.startswith('0x'):
                addr = dbg.to_int(addr)
            else:
                addr = dbg.to_int('0x%s' % (addr))
        except:
            print('[shadow] invalid address parameter')
            sys.exit()

        shadow.dump_run(addr, view_maps)

    elif sys.argv[1] == 'symbol':
        size = 0
        vtable = False
        mozjs = False
        xul = False
        dom = False

        try:

            alist, args = getopt.getopt(sys.argv[2:], 'vjdx')

            for (field, val) in alist:

                if field in '-v':
                    vtable = True

                if field in '-j':
                    mozjs = True

                if field in '-d':
                    dom = True

                if field in '-x':
                    xul = True

            size = int(args[0])

            if mozjs == dom == xul == False:
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
        search_current_runs = False
        size_class = 0

        try:

            alist, args = getopt.getopt(sys.argv[2:], 'cs:')

            for (field, val) in alist:

                if field in '-c':
                    search_current_runs = True

                if field in '-s':
                    size_class = int(val)

            search_for = args[0:]
            if not search_for:
                sys.exit()

        except:
            print('[shadow] usage: jesearch [-cs] <hex dword>')
            print('[shadow] options:')
            print('[shadow]    -c           search current runs only')
            print('[shadow]    -s <size>    regions of the given size only')
            print('[shadow] for example: jesearch -c -s 256 0x41424344')
            sys.exit()

        shadow.search(search_for, size_class, search_current_runs, False)

    sys.exit()

# EOF
