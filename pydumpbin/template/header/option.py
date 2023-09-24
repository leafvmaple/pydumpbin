from pydumpbin.node import Node


def __init__(node: Node, file, json_data, py_data):
    node.decrypt(file, json_data, py_data)
    if node._data['Magic'] == 0x10b:
        node.decrypt(file, json_data['-PE32'], py_data)
    else:
        node.decrypt(file, json_data['-PE32+'], py_data)
