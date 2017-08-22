# shadow - De Mysteriis Dom jemalloc

import os
import sys

sys.path.insert(1, os.path.join(sys.path[0], '..'))
import jemalloc

def main():

    if len(sys.argv) <= 1:
        print("usage: %s snapshot_path" % sys.argv[0])
        sys.exit(1)

    snapshot_path = sys.argv[1]

    jeheap = jemalloc.jemalloc(path=snapshot_path)

    for chunk in jeheap.chunks:
        print "chunk @ 0x%x has %d runs." % (chunk.addr, len(chunk.runs))

if __name__ == "__main__":
    main()

# EOF
