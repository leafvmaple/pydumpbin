from pydumpbin.node import Node


def Flags(node: Node, file, json_data, py_data):
    x64 = node._root.FileHeader.EI_CLASS == 2
    node.decrypt_platform(file, json_data, py_data, x64=x64)


def Address(node: Node, file, json_data, py_data):
    x64 = node._root.FileHeader.EI_CLASS == 2
    node.decrypt_platform(file, json_data, py_data, x64=x64)


def Offset(node: Node, file, json_data, py_data):
    x64 = node._root.FileHeader.EI_CLASS == 2
    node.decrypt_platform(file, json_data, py_data, x64=x64)


def Size(node: Node, file, json_data, py_data):
    x64 = node._root.FileHeader.EI_CLASS == 2
    node.decrypt_platform(file, json_data, py_data, x64=x64)


def Align(node: Node, file, json_data, py_data):
    x64 = node._root.FileHeader.EI_CLASS == 2
    node.decrypt_platform(file, json_data, py_data, x64=x64)


def EntSize(node: Node, file, json_data, py_data):
    x64 = node._root.FileHeader.EI_CLASS == 2
    node.decrypt_platform(file, json_data, py_data, x64=x64)
