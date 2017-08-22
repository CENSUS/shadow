# shadow - De Mysteriis Dom jemalloc

import os
import sys
import argparse
import pickle
import comtypes
import comtypes.client

import symbol

# this has to be before the import that follows
msdia = comtypes.client.GetModule('msdia\\msdia90.dll')

from comtypes.gen.Dia2Lib import *

# https://msdn.microsoft.com/en-us/library/wcstk66t.aspx
udtEnumToStr = ('struct', 'class', 'union', 'interface')

# get a handle to the DIA COM object
def getDIAObj():
    global msdia

    try:
        dia = comtypes.client.CreateObject(msdia.DiaSource)
    except Exception as exc:
        print "Exception creating DIA object: %s\nTry to regsrv32.dll msdia90.dll" % (str(exc))
        sys.exit(1)
    return dia

# parse the PDB
def loadPDB(dia, pdbFile):
    try:
        dia.loadDataFromPdb(pdbFile)
        return dia.openSession()
    except Exception as exc:
        print('[!] loadDataFromPdb() error %s' % (str(exc)))
        sys.exit(1)

# convert a cygwin path to a windows path if needed
def convertPath(path):
    if path.find("/") == -1:
        return path
    elif path.startswith("/cygdrive/"):
        pieces = path.split("/")
        return pieces[2] + ":\\" + "\\".join(pieces[3:])
    else:
        return path.replace('/', '\\')

# load up the symbol list
def loadPickle(pfile):
    pfd = open(pfile, 'rb')
    syms = pickle.load(pfd)
    pfd.close()
    return syms

# store the symbol list
def storePickle(syms, pdbFileName):
    outFile = '%s.pkl' % (pdbFileName)
    pfd = open(outFile, 'wb')
    pickle.dump(syms, pfd)
    pfd.close()
    print "Created pickle file %s" % (outFile)

# parse the input PDB
def parsePDB(pdbObj):
    syms = set()
    vfts = set()

    # iterate the public syms to find all vtables
    for symb in pdbObj.globalScope.findChildren(SymTagPublicSymbol, None, 0):
        symbol_data = symb.QueryInterface(IDiaSymbol)

        full_name = symbol_data.undecoratedName
        vft_idx = full_name.find("::`vftable'")
        if vft_idx == -1:
            continue

        symbol_name = full_name[6:vft_idx]
        vfts.add(symbol_name)

    # iterate all UDT/private? symbols
    for symb in pdbObj.globalScope.findChildren(SymTagUDT, None, 0):
        symbol_data = symb.QueryInterface(IDiaSymbol)

        hasVFT = symbol_data.name in vfts
        symbol_obj = symbol.symbol(udtEnumToStr[symbol_data.udtKind], symbol_data.name,
                                                            symbol_data.length, hasVFT)

        syms.add(symbol_obj)

    return list(syms)

# main
def do_main():
    parser = argparse.ArgumentParser(description="PDB type search")
    parser.add_argument('-f', '--pdbFile', required=True, help="The target PDB file.")
    parser.add_argument('-p', '--pickleFile', required=False, help="The target pickle file.")
    parser.add_argument('-v', '--verbose', default=False, action='store_true', help='Verbose output')
    args = parser.parse_args()

    pdbFile = convertPath(args.pdbFile)

    # parse/load the PDB
    dia = getDIAObj()
    pdbObj = loadPDB(dia, pdbFile)

    # if a pickle is provided, use that for the initial type list
    # if not, parse the types from the PDB
    if args.pickleFile:
        print "Loading type list from pickle."
        syms = loadPickle(convertPath(args.pickleFile))
    else:
        print "Loading type list from PDB %s." % (pdbFile)
        syms = parsePDB(pdbObj)
        storePickle(syms, os.path.basename(pdbFile))

    # we have the types, now what.

    print "Found %d total types." % (len(syms))
    for sym in syms:
        print('%s' % (sym))

if __name__ == '__main__':
    do_main()

# EOF
