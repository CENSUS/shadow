# shadow - De Mysteriis Dom jemalloc

def detect_dbg_engine():
    try:
        import gdb
        import gdb_engine
        return (gdb_engine, 'gdb')
    except ImportError:
        pass

    try:
        import pykd
        import pykd_engine
        if pykd.isWindbgExt():
            return (pykd_engine, 'pykd')
    except ImportError:
        pass

    try:
        import lldb
        import lldb_engine
        return (lldb_engine, 'lldb')
    except ImportError:
        pass

dbg, dbg_engine = detect_dbg_engine()
