from pydumpbin.utils import read
from pydumpbin.node import Node

MAGIC = b"!<arch>\n"
EXT = [".lib"]


def ObjectFiles(node: Node, file, json_data, py_data):
    node.decrypt(file, json_data, py_data)

    machine = read(file, "*u2")
    file.seek(file.tell() - 2)
    tell = file.tell()
    if machine != 0:
        node.decrypt(file, json_data["-LongFormat"], py_data)

        for section in node['SectionHeaders']:
            file.seek(tell + int(section['PointerToRawData']))
            section['RawData'] = file.read(int(section['SizeOfRawData']))

            if section['NumberOfRelocations'] > 0:
                file.seek(tell + int(section['PointerToRelocations']))
                section['Relocations'] = [Node(file, "header/relocation.json", py_data) for i in range(int(section['NumberOfRelocations']))]

    else:
        node.decrypt(file, json_data["-ShortFormat"], py_data)

    file.seek(tell + int(node['ArchiveMemberHeader']['Size']))

    while file.read(1) == b'\n':
        pass
    file.seek(file.tell() - 1)


def SectionHeaders(file, json_data, py_data):
    pass
