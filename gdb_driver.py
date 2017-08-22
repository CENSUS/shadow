# shadow - De Mysteriis Dom jemalloc

import os
import sys
import getopt
import warnings

sys.path.append(os.path.dirname(os.path.realpath(__file__)))

import shadow
import gdb_engine as dbg


class jemalloc_help(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jehelp', gdb.COMMAND_OBSCURE)

    def invoke(self, arg, from_tty):
        shadow.help()


class jemalloc_version(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jeversion', gdb.COMMAND_OBSCURE)

    def invoke(self, arg, from_tty):
        shadow.version()


class jemalloc_parse(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jeparse', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        read_content_preview = False
        do_debug_log = False
        config_path = None

        arg = arg.split()
        for i in range(len(arg)):
            if arg[i] == "-r":
                read_content_preview = True
            if arg[i] == "-v":
                do_debug_log = True

            elif arg[i] == "-c":
                if i + 1 >= len(arg):
                    print('[shadow] empty configuration path')
                    return
                config_path = arg[i+1]
                if not os.path.isfile(config_path):
                    print('[shadow] configuration file not found')
                    return

        shadow.parse(read_content_preview, config_path, do_debug_log=do_debug_log)


class jemalloc_dump(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jedump', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        arg = arg.split()
        if len(arg) == 0:
            path = None
        else:
            path = arg[0]

        shadow.dump_all(path=path)


class jemalloc_chunks(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'jechunks', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        arg = arg.split()
        try:
            alist, args = getopt.getopt(arg, 'a:')

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
            return

        shadow.dump_chunks()


class jemalloc_chunk(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jechunk', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        arg = arg.split()

        try:
            addr = arg[0]

            if addr.startswith('0x'):
                addr = dbg.to_int(addr)
            else:
                addr = dbg.to_int('0x%s' % (addr))
        except:
                print('[shadow] usage: jechunk <address>')
                print('[shadow] for example: jechunk 0x900000')
                return

        shadow.dump_chunk(addr)



class jemalloc_arenas(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'jearenas', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        shadow.dump_arenas()


class jemalloc_runs(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jeruns', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        arg = arg.split()
        current_runs = False
        size = 0

        try:

            alist, args = getopt.getopt(arg, 'cs:')

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
            return

        shadow.dump_runs(dump_current_runs = current_runs, size_class = size)


class jemalloc_run(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jerun', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        arg = arg.split()

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
            return

        try:
            if addr.startswith('0x'):
                addr = dbg.to_int(addr)
            else:
                addr = dbg.to_int('0x%s' % (addr))
        except:
            print('[shadow] invalid address parameter')
            return

        shadow.dump_run(addr, view_maps)


class jemalloc_bins(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jebins', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        shadow.dump_bins()


class jemalloc_regions(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jeregions', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        if arg == '':
            print('[shadow] usage: jeregions <size class>')
            print('[shadow] for example: jeregions 1024')
            return

        if arg.startswith('0x'):
            size_class = int(arg, 16)
        else:
            size_class = int(arg)

        shadow.dump_regions(size_class)


class jemalloc_search(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jesearch', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        search_for = ''
        current_runs = False
        address_space = False
        quick = False
        size_class = 0
        filled_holes = False

        try:
            arg = arg.split()
            alist, args = getopt.getopt(arg, 'cs:qfa')

            for (field, val) in alist:

                if field in '-c':
                    current_runs = True

                if field in '-a':
                    address_space = True


                if field in '-s':
                    size_class = int(val)

                if field in '-q':
                    quick = True

                if field in '-f':
                    filled_holes = True
                    shadow.show_filled_holes()
                    break

            if filled_holes == True:
                return

            search_for = args[0:]
            if not search_for:
                return

        except:

            if filled_holes == True:
                return

            print('[shadow] usage: jesearch [-cfqs] <hex dword>')
            print('[shadow] options:')
            print('[shadow]    -c           search current runs only')
            print('[shadow]    -s <size>    regions of the given size only')
            print('[shadow] for example: jesearch -c -s 256 0x41424344')
            print('[shadow]          or: jesearch -f')
            return

        if filled_holes == False:
            shadow.search(search_for, size_class, current_runs, address_space)


class jemalloc_info(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jeinfo', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        arg = arg.split()

        try:
            if arg[0].startswith('0x'):
                addr = dbg.to_int(arg[0])
            else:
                addr = dbg.to_int('0x%s' % (arg[0]))
        except:
            print('[shadow] usage: jeinfo <address>')
            print('[shadow] for example: jeinfo 0x079e5440')
            return

        shadow.dump_address(addr)


class jemalloc_store(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jestore', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        if len(arg) == 0:
            print('[shadow] usage: jestore /path/')
            return

        path = arg
        shadow.store_jeheap(path)


class jemalloc_tcaches(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jetcaches', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        shadow.dump_tcaches()


class jemalloc_jefreecheck(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jefreecheck', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            binind = None
            module_name = None

            arg = arg.split()
            alist, args = getopt.getopt(arg, 'b:m:')

            for (field, val) in alist:
                if field in '-b':
                    if val.startswith('0x'):
                        binind = int(val, 16)
                    else:
                        binind = int(val)

                if field in '-m':
                    module_name = val

        except:
            print('[shadow] usage: jefreecheck -b <bin index> -m <name>')
            print('[shadow] for example: jefreecheck -b 0 -m libart.so')
            return
        if binind is None and module_name is None:
            print('[shadow] No bin index or module name specified, this will take long.')

        try:
            shadow.jefreecheck(binind, module_name)
        except KeyboardInterrupt:
            print('[shadow] Aborted by user.')
            return


class jemalloc_bininfo(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jebininfo', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        shadow.dump_bin_info()


class jemalloc_tcache(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, "jetcache", gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        tid = gdb.selected_thread().ptid[1]
        size = None
        binind = None

        arg = arg.split()
        alist, args = getopt.getopt(arg, "b:s:")

        for (field, val) in alist:
            if field == "-b":
                try:
                    if val.startswith('0x'):
                        binind = int(val, 16)
                    else:
                        binind = int(val)
                except:
                    print("[shadow] %s is not a valid number." % val)

            if field == "-s":
                try:
                    if val.startswith('0x'):
                        size = int(val, 16)
                    else:
                        size = int(val)
                except:
                    print("[shadow] %s is not a valid number." % val)

        if len(args) > 0:
            try:
                if args[0].startswith('0x'):
                    tid = int(args[0], 16)
                else:
                    tid = int(args[0])
            except:
                print("[shadow] %s is not a valid number")

        if size != None and binind != None:
            print("[shadow] Specify either a bin index or an allocation size;"
                  " not both.")
            return

        shadow.dump_tcache(tid, binind, size)


class jemalloc_size2bin(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jesize2bin', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        arg = arg.split()

        try:
            if arg[0].startswith('0x'):
                size = int(arg[0], 16)
            else:
                size = int(arg[0])
        except:
            print('[shadow] usage: jesize2bin <size>')
            print('[shadow] for example: jesize2bin 0x100')
            return

        shadow.print_size2binind(size)

# required for classes that implement gdb commands
jemalloc_help()
jemalloc_version()
jemalloc_parse()
jemalloc_dump()
jemalloc_chunk()
jemalloc_chunks()
jemalloc_arenas()
jemalloc_runs()
jemalloc_run()
jemalloc_bins()
jemalloc_regions()
jemalloc_search()
jemalloc_info()
jemalloc_store()
jemalloc_tcaches()
jemalloc_tcache()
jemalloc_jefreecheck()
jemalloc_bininfo()
jemalloc_size2bin()
# EOF
