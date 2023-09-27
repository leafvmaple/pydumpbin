from pydumpbin.node import Node


def __del__(node: Node, file, json_data, py_data):
    obj = node._parent._parent
    size = int(node.SizeOfRawData)

    if size > 0:
        node['+Raw'] = Node()
        node['+Raw'].decrypt_raw(file, obj.FileHeader._begin + int(node.PointerToRawData), size)

    size = int(node.NumberOfRelocations)
    if size > 0:
        node['+Relocations'] = Node(root=node._root, parent=node)
        node['+Relocations'].decrypt_offset(file, json_data['-Relocations'], py_data, obj.FileHeader._begin + int(node.PointerToRelocations))
