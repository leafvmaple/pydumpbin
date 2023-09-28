from pydumpbin.node import Node
from pydumpbin.utils import get_format
import capstone


def Flags(node: Node, file, json_data, py_data):
    node.decrypt_with_platform(file, json_data, py_data, x64=node._root._AMD64)


def Address(node: Node, file, json_data, py_data):
    node.decrypt_with_platform(file, json_data, py_data, x64=node._root._AMD64)


def Offset(node: Node, file, json_data, py_data):
    node.decrypt_with_platform(file, json_data, py_data, x64=node._root._AMD64)


def Size(node: Node, file, json_data, py_data):
    node.decrypt_with_platform(file, json_data, py_data, x64=node._root._AMD64)


def Align(node: Node, file, json_data, py_data):
    node.decrypt_with_platform(file, json_data, py_data, x64=node._root._AMD64)


def EntSize(node: Node, file, json_data, py_data):
    node.decrypt_with_platform(file, json_data, py_data, x64=node._root._AMD64)


def __del__(node: Node, file, json_data, py_data):
    offset = int(node.Offset)
    size = int(node.Size)
    if size > 0:
        if node.Type == 'RELA':
            cnt = int(node.Size) // 24
            format = [get_format(node._format['-RelocationA'], node._root._AMD64)] * cnt
            node['+Relocations'] = Node(key='Relocations').decrypt_with_offset(file, format, {}, int(node.Offset))
        elif node.Type == 'PROGBITS':
            if 'EXECUTE' in node.Flags._desc:
                node['+Assembly'] = Node().decrypt_assembly(file, offset, size)
            else:
                node['+Raw'] = Node().decrypt_raw(file, offset, size)
        else:
            node['+Raw'] = Node().decrypt_raw(file, offset, size)
