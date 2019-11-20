# shadow - De Mysteriis Dom jemalloc

dbg = None
dbg_engine = 'unknown'

# detect debugger engine
try:
    import gdb
    import gdb_engine as dbg
    dbg_engine = 'gdb'
except ImportError:
    try:
        import pykd
        import pykd_engine as dbg
        if pykd.isWindbgExt():
            dbg_engine = 'pykd'
    except ImportError:
        try:
            import lldb
            import lldb_engine as dbg
            dbg_engine = 'lldb'
        except ImportError:
            pass
