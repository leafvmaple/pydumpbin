from pydumpbin.node import Node


def Flags(node: Node, file, json_data, py_data):
    x64 = node._root.ELFHeader.Class == 2
    node.decrypt_platform(file, json_data, py_data, x64=x64)


def Address(node: Node, file, json_data, py_data):
    x64 = node._root.ELFHeader.Class == 2
    node.decrypt_platform(file, json_data, py_data, x64=x64)


def Offset(node: Node, file, json_data, py_data):
    x64 = node._root.ELFHeader.Class == 2
    node.decrypt_platform(file, json_data, py_data, x64=x64)


def Size(node: Node, file, json_data, py_data):
    x64 = node._root.ELFHeader.Class == 2
    node.decrypt_platform(file, json_data, py_data, x64=x64)


def Align(node: Node, file, json_data, py_data):
    x64 = node._root.ELFHeader.Class == 2
    node.decrypt_platform(file, json_data, py_data, x64=x64)


def EntSize(node: Node, file, json_data, py_data):
    x64 = node._root.ELFHeader.Class == 2
    node.decrypt_platform(file, json_data, py_data, x64=x64)


def Raw(node: Node, file, json_data, py_data):
    offset = int(node._parent.Offset)
    size = int(node._parent.Size)
    if size > 0:
        node.decrypt_raw(file, offset, size)


def __del__(node: Node, file, json_data, py_data):
    offset = int(node.Offset)
    size = int(node.Size)
    if size > 0:
        node['+Raw'] = Node()
        node['+Raw'].decrypt_raw(file, offset, size)
