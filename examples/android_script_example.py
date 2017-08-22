# shadow - De Mysteriis Dom jemalloc
#
# This script searches for regions whose first dword points
# to module_name + offset. Change these to your liking.

module_name = "libskia.so"
offset = 0x5528d8
region_size = 0xc0

# dbg engine is already loaded in process
dbg = shadow.dbg

# the parsed heap object created by the jeparse command
jeheap = shadow.jeheap

if not jeheap:
    # we don't use sys.exit() because it kills the debugging session
    raise("No parsed heap object found, use jeparse.")

if module_name not in jeheap.modules_dict:
    raise("%s module not found in proccess." % module_name)

module_addr_ranges = jeheap.modules_dict[module_name]
module_start_addr = module_addr_ranges[0][0]

print("%s loaded at 0x%x" % (module_name, module_start_addr))

vft_ptr = module_start_addr + offset

print("Searching for 0x%x sized regions that point to %s + 0x%x" %
      (region_size, module_name, offset))



found_regions = []
target_binind = shadow.size2binind(jeheap, region_size)
for addr, run in jeheap.runs.items():
    # skip large runs
    if run.binind == 0xff:
        continue

    # skip runs that don't belong to our target region_size
    if run.binind != target_binind:
        continue

    for region in run.regions:
        first_dword = dbg.read_dword(region.addr)
        if first_dword == vft_ptr:
            found_regions.append(region)

print("Found %d regions." % len(found_regions))
for region in found_regions:
    if region.is_free:
        state = "free"
    else:
        state = "busy"
    print("  - 0x%x (%s)" % (region.addr, state))

# EOF
