# shadow - De Mysteriis Dom jemalloc

from dbg import dbg

class pthread_internal:
    '''
    An object of type pthread_internal_t
    '''
    def __init__(self, addr):
        size = dbg.sizeof("pthread_internal_t")

        # Keep this as a cache
        self.data = dbg.read_bytes(addr, size)

        self.tid = dbg.read_struct_member(self.data, "pthread_internal_t",
                                           "tid", dbg.int_size())
        self.next = dbg.read_struct_member(self.data, "pthread_internal_t",
                                           "next", dbg.get_dword_size())

    def get_key_data(self):
        # We need to handle two cases. key_data being a member of
        # pthread_internal_t (Android 6-9) and key_data being a member of
        # bionic_tls which is a member of pthread_internal_t (Android 10).
        try:
            BIONIC_PTHREAD_KEY_COUNT = 130
            bionic_tls = dbg.read_struct_member(self.data, "pthread_internal_t",
                                           "bionic_tls", dbg.get_dword_size())
            offset = bionic_tls + dbg.offsetof("bionic_tls", "key_data")
            size = dbg.sizeof('pthread_key_data_t') * BIONIC_PTHREAD_KEY_COUNT
            return pthread_key_data(dbg.read_bytes(offset, size))

        except:
            BIONIC_PTHREAD_KEY_COUNT = 141
            offset = dbg.offsetof('pthread_internal_t', 'key_data')
            size = dbg.sizeof('pthread_key_data_t') * BIONIC_PTHREAD_KEY_COUNT
            key_data = self.data[offset:offset+size]
            return pthread_key_data(key_data)



class pthread_key_data:
    '''
    An array of pthread_key_data_t objects.
    NOTE: Put the key_data in a colection (eg an array of tuples) if used more
    than once.
    '''
    def __init__(self, data):
        self.data = data

    def get_data_list(self):
        off = dbg.offsetof('pthread_key_data_t', 'data')
        step = dbg.sizeof('pthread_key_data_t')
        key_data_data = []
        while off < len(self.data):
            datum = dbg.dword_from_buf(self.data, off)
            key_data_data.append(datum)
            off += step
        return key_data_data

