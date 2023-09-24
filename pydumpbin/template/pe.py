import sys

_MZ = b'MZ'
_PE = b'PE\0\0'

LIB = [".dll"]


def MAGIC(file):
    if _MZ != file.read(len(_MZ)):
        return False
    file.seek(0x3c)
    sign_offset = int.from_bytes(file.read(4), byteorder=sys.byteorder)
    if sign_offset <= 0:
        return False

    file.seek(sign_offset)
    return _PE == file.read(len(_PE))
