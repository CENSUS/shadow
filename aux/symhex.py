import os
import sys
import cPickle as pickle
import comtypes
import comtypes.client

sys.path.append('..')
import symbol

false = False
true = True
none = None

msdia = comtypes.client.GetModule('msdia\\msdia90.dll')
from comtypes.gen.Dia2Lib import *

# comtypes.gen.Dia2Lib.SymTagUDT
sym_tag_udt = SymTagUDT

# comtypes.gen.Dia2Lib.SymTagPublicSymbol
sym_tag_public_symbol = SymTagPublicSymbol

udt_str = ('struct', 'class', 'union')

# the list of symbol objects
symbol_list = []

def init_msdia():
    global msdia

    try:
        dia_obj = comtypes.client.CreateObject(msdia.DiaSource)
    except:
        os.system('regsvr32 /s msdia\\msdia90.dll')
        dia_obj = comtypes.client.CreateObject(msdia.DiaSource)

    return dia_obj

if __name__ == '__main__':
    argc = len(sys.argv)

    if argc < 2:
        print('[*] usage: %s <pdb file>' % (sys.argv[0]))
        sys.exit()

    pdb_file = sys.argv[1]

    dia = init_msdia()

    try:
        dia.loadDataFromPdb(pdb_file)
    except:
        print('[!] loadDataFromPdb() error')
        sys.exit()

    pdb = dia.openSession()

    for symb in pdb.globalScope.findChildren(sym_tag_udt, none, 0):
        symbol_data = symb.QueryInterface(IDiaSymbol)

        symbol_obj = symbol.symbol(udt_str[symbol_data.udtKind], symbol_data.name, \
                symbol_data.length, false)
        
        if symbol_obj not in symbol_list:
            symbol_list.append(symbol_obj)

    for symb in pdb.globalScope.findChildren(sym_tag_public_symbol, none, 0):
        symbol_data = symb.QueryInterface(IDiaSymbol)

        full_name = symbol_data.undecoratedName
        vft_idx = full_name.find("::`vftable'")
        
        if vft_idx == -1:
            continue

        symbol_name = full_name[6:vft_idx]

        for (i, obj) in enumerate(symbol_list):
            if obj.name == symbol_name:
                symbol_list[i] = symbol.symbol(obj.kind, obj.name, obj.size, true)

    pickle_file = './%s.pkl' % (pdb_file)
    pfd = open(pickle_file, 'wb')
    pickle.dump(symbol_list, pfd)
    pfd.close()

    pfd = open(pickle_file, 'rb')
    s_list = pickle.load(pfd)
    pfd.close()

    for sym in s_list:
        print('%s' % (sym))

# EOF
