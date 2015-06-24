# shadow - De Mysteriis Dom Firefox

import os
import sys
import warnings

sys.path.append('.')

import shadow

true = True
false = False
none = None

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
        shadow.parse(proc = self.proc)

class jemalloc_dump(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jedump', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        if arg == '':
            screen = true
        else:
            screen = false

        shadow.dump_all(filename = arg, \
                dump_to_screen = screen, proc = self.proc)

class jemalloc_chunks(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jechunks', gdb.COMMAND_OBSCURE)
       
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        shadow.dump_chunks(proc = self.proc)

class jemalloc_arenas(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jearenas', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        shadow.dump_arenas(proc = self.proc)

class jemalloc_runs(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jeruns', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        arg = arg.split()

        if len(arg) >= 1 and arg[0] == '-c':
            current_runs = true
        else:
            current_runs = false

        shadow.dump_runs(dump_current_runs = current_runs, \
                proc = self.proc)

class jemalloc_bins(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jebins', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        shadow.dump_bins(proc = self.proc)

class jemalloc_regions(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jeregions', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):

        if arg == '':
            print('[shadow] usage: jeregions <size class>')
            print('[shadow] for example: jeregions 1024')
            return

        size_class = int(arg)
        shadow.dump_regions(size_class, proc = self.proc)

class jemalloc_search(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'jesearch', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        if arg == '':
            print('[shadow] usage: jesearch [-c] <hex dword>')
            print('[shadow] Use -c to search current runs only')
            print('[shadow] for example: jesearch 0x41424344')
            return

        arg = arg.split()
        if len(arg) >= 2 and arg[0] == '-c':
            current_runs = true
            search_for = arg[1]
        else:
            current_runs = false
            search_for = arg[0]

        shadow.search(search_for, \
                search_current_runs = current_runs, proc = self.proc)

# required for classes that implement gdb commands

jemalloc_help()
jemalloc_version()
jemalloc_parse()
jemalloc_dump()
jemalloc_chunks()
jemalloc_arenas()
jemalloc_runs()
jemalloc_bins()
jemalloc_regions()
jemalloc_search()

# EOF
