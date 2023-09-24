from pydumpbin.node import Node

MAGIC = b'\x7fELF'


def Entry(node: Node, file, json_data, py_data):
    x64 = node._root.FileHeader.EI_CLASS == 2
    node.decrypt_platform(file, json_data, py_data, x64=x64)


def ProgramHeaderOffset(node: Node, file, json_data, py_data):
    x64 = node._root.FileHeader.EI_CLASS == 2
    node.decrypt_platform(file, json_data, py_data, x64=x64)


def SectionHeaderOffset(node: Node, file, json_data, py_data):
    x64 = node._root.FileHeader.EI_CLASS == 2
    node.decrypt_platform(file, json_data, py_data, x64=x64)


def SectionHeaders(node: Node, file, json_data, py_data):
    root = node._root
    file.seek(int(root.FileHeader.SectionHeaderOffset))
    node.decrypt(file, json_data, py_data)
