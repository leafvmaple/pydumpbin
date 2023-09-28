import undname

from pydumpbin.utils import read
from pydumpbin.node import Node

MAGIC = b"!<arch>\n"
EXT = [".lib"]


def StringTable(node: Node, file, json_data, py_data):
    node.decrypt(file, json_data, py_data)

    for sub in node._data:
        if sub._data.startswith('__imp_'):
            sub._desc = '__imp__ ' + undname.undname(sub._data[6:])
        else:
            sub._desc = undname.undname(sub._data)


def ObjectFile(node: Node, file, json_data, py_data):
    node.decrypt(file, json_data, py_data)

    machine = read(file, "*u2")
    file.seek(file.tell() - 2)
    tell = file.tell()

    node.decrypt_with_platform(file, json_data, py_data, x64=machine != 0)

    file.seek(tell + int(node['ArchiveMemberHeader']['Size']))

    while file.read(1) == b'\n':
        pass
    file.seek(file.tell() - 1)
