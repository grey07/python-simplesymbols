from uuid import UUID
from os.path import basename
from traceback import format_exc
from optparse import OptionParser
from sys import stdout, exit, argv
from struct import unpack, calcsize
from ntpath import basename as ntbasename
from pefile import PE, DIRECTORY_ENTRY, DEBUG_TYPE
from urllib2 import Request, urlopen, build_opener
from logging import getLogger, StreamHandler, Formatter, DEBUG
from construct import Struct, Const, Bytes, ULInt32, ULInt16, CString, String

# Symbol Servers:
# Microsoft: http://msdl.microsoft.com/download/symbols/
# Mozilla Firefox: http://symbols.mozilla.org/
# Google Chrome: https://chromium-browser-symsrv.commondatastorage.googleapis.com

def GUID(name):
    return Struct(name,
        ULInt32("Data1"),
        ULInt16("Data2"),
        ULInt16("Data3"),
        String("Data4", 8))

CV_RSDS_HEADER = Struct("CV_RSDS",
    Const(Bytes("Signature", 4), "RSDS"),
    GUID("GUID"),
    ULInt32("Age"),
    CString("Filename"))

CV_NB10_HEADER = Struct("CV_NB10",
    Const(Bytes("Signature", 4), "NB10"),
    ULInt32("Offset"),
    ULInt32("Timestamp"),
    ULInt32("Age"),
    CString("Filename"))

logger = getLogger("symfetch")
RSDS_TYPE_STRING = "<I16BI"

def parse_arguments():
    usage = 'usage: %prog [options] pe_file'
    parser = OptionParser(usage=usage)

    parser.add_option('-q',
        '--quiet',
        action='store_true',
        default=False,
        dest='quiet',
        help='When passed in turns off console output.')

    parser.add_option('-s',
        '--symbol_server',
        type='string',
        dest='symbol_server',
        default='http://msdl.microsoft.com/download/symbols/',
        help='The URL of the symbol server to use for the request.')

    options, args = parser.parse_args()

    if len(argv) == 1:
        parser.print_help()
        exit(1)
    elif len(args) != 1:
        parser.error("You must pass the path to the pe file as an argument")

    return args, options

def __fetch__(symbol_server, guid, file_name, pdb_filename):
    '''
        Reach out and actually make the request. This will return the raw result from the symbol
        server, which is usually a symbol compressed in a cabinet file.

        Failures will return None.
    '''
    try:
        assert symbol_server
        assert guid
        assert file_name
        assert pdb_filename

        guid = guid.replace('-', '').upper()

        if symbol_server.endswith('/') or symbol_server.endswith('\\'):
            symbol_server = symbol_server[:-1]

        url = '{0}/{1}/{2}/{3}.pd_'.format(symbol_server, pdb_filename, guid, pdb_filename[:-4])
        logger.info("Fetching %s", url)
        request = Request(url)
        request.add_header('Cache-Control', 'no-cache')
        request.add_header('User-Agent', 'Microsoft-Symbol-Server/6.12.0002.633')
        response = urlopen(request)

        logger.info("Response Header:\n%s", response.info())

        if response.info().get('Content-Length', '0') == 0:
            logger.warn("No data returned from symbol server")
            return None

        return response.read()

    except Exception:
        logger.error(format_exc())
        return None

def parse_pe_fetch_pdb(symbol_server, file_path):
    '''
        Attempt to fetch a symbol that relates to a PE file. The file must have a
        valid IMAGE_DEBUG_DIRECTORY and as well as a IMAGE_DEBUG_TYPE_CODEVIEW directroy
        entry.
    '''
    try:
        guid = None
        pdb_filename = None
        pe = PE(file_path, fast_load=True)
        pe.parse_data_directories(directories=[DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']])

        code_view_entry = None
        for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
            if DEBUG_TYPE[debug_entry.struct.Type] == "IMAGE_DEBUG_TYPE_CODEVIEW":
                code_view_entry = debug_entry
                break

        if code_view_entry == None:
            logger.warn("%s doesn't have symbol information", basename(file_path))
            return None, None

        symbol_type_offset = code_view_entry.struct.PointerToRawData
        symbol_type_size = code_view_entry.struct.SizeOfData
        symbol_type_data = pe.__data__[symbol_type_offset:symbol_type_offset+symbol_type_size]

        if symbol_type_data[:4] == "RSDS":
            rsds = CV_RSDS_HEADER.parse(symbol_type_data)
            guid = "%08x%04x%04x%s%x" % (rsds.GUID.Data1, rsds.GUID.Data2, rsds.GUID.Data3, rsds.GUID.Data4.encode('hex'), rsds.Age)
            pdb_filename = ntbasename(rsds.Filename)
        elif symbol_type_data[:4] == "NB10":
            nb10 = CV_NB10_HEADER.parse(symbol_type_data)
            guid = "%x%x" % (nb10.Timestamp, nb10.Age)
            pdb_filename = ntbasename(nb10.Filename)
        else:
            logger.error("%s unsupported symbol type", symbol_type_data[:4])
            return None, None

        assert guid
        assert pdb_filename

        symbol = __fetch__(symbol_server, guid, file_path, pdb_filename)

        if symbol[:4] == 'MSCF':
            # TODO, unpack cabinet
        else:
            logger.error("Excpected symbol server to return a cabinet file")
            return None, None

        return symbol, basename(pdb_filename)
    except Exception:
        logger.error(format_exc())
        return None, None

if __name__ == "__main__":
    args, options = parse_arguments()

    if not options.quiet:
        stream_handler = StreamHandler()
        stream_handler.setLevel(DEBUG)
        stream_handler.setFormatter(Formatter('%(asctime)s - %(name)s - %(levelname)s: %(message)s'))
        logger.setLevel(DEBUG)
        logger.addHandler(stream_handler)

    symbol, symbol_name = parse_pe_fetch_pdb(options.symbol_server, args[0])

    if symbol_name and symbol:
        symbol_file = open(symbol_name, 'wb')
        symbol_file.write(symbol)
        symbol_file.close()
