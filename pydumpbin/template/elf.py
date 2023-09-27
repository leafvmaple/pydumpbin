from pydumpbin.node import Node

MAGIC = b'\x7fELF'


def Entry(node: Node, file, json_data, py_data):
    x64 = node._root.ELFHeader.Class == 2
    node.decrypt_platform(file, json_data, py_data, x64=x64)


def ProgramHeaderOffset(node: Node, file, json_data, py_data):
    x64 = node._root.ELFHeader.Class == 2
    node.decrypt_platform(file, json_data, py_data, x64=x64)


def SectionHeaderOffset(node: Node, file, json_data, py_data):
    x64 = node._root.ELFHeader.Class == 2
    node.decrypt_platform(file, json_data, py_data, x64=x64)


def SectionHeaders(node: Node, file, json_data, py_data):
    root = node._root
    file.seek(int(root.ELFHeader.SectionHeaderOffset))
    node.decrypt(file, json_data, py_data)


def __del__(node: Node, file, json_data, py_data):
    idx = int(node.ELFHeader.SectionHeaderStringIndex)
    raw = node.SectionHeaders[idx]['+Raw']

    for i, secion in enumerate(node.SectionHeaders):
        start = int(secion.Name)
        end = raw._raw.find(b'\x00', int(secion.Name))
        secion.Name._desc = raw._raw[start: end].decode()
        # secion.Name._display = strs[i]
