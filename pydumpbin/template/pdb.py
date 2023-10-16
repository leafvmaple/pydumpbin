import pdbparse

from pydumpbin.node import Node
from pydumpbin.utils import File, pages

gdb = None
MAGIC = b'Microsoft'


def __init__(node: Node, file, json_data, py_data):
    py_data['gdb'] = pdbparse.PDB7(file, True)
    file.seek(0)


# The Page Number List of the Root Page Number List
def RootPagesPageNum(node: Node, file, json_data, py_data):
    page_size = int(node._root.PageSize)
    root_pages = pages(int(node._parent.RootStreamSize), page_size)
    root_indies_pages = pages(root_pages * 4, page_size)
    node.decrypt(file, ["*u4"] * root_indies_pages, py_data)


def RootPages(node: Node, file, json_data, py_data):
    page_size = int(node._root.PageSize)
    root_pages = pages(int(node._parent.RootStreamSize), page_size)
    root_pages_data = []
    for root_pages_page in node._parent.RootPagesPageNum._data:
        file.seek(int(root_pages_page) * page_size)
        root_pages_data.append(file.read(page_size))
    data = b''.join(root_pages_data)
    node.decrypt(File(data, int(node._parent.RootPagesPageNum._data[0]) * page_size), ["*u4"] * root_pages, py_data)


def RootStream(node: Node, file, json_data, py_data):
    page_size = int(node._root.PageSize)

    root_data = []
    for page in node._parent.RootPages._data:
        file.seek(int(page) * page_size)
        root_data.append(file.read(page_size))
    data = b''.join(root_data)

    node.decrypt(File(data, int(node._parent.RootPages._data[0]) * page_size), json_data, py_data)


def StreamSize(node: Node, file, json_data, py_data):
    node.decrypt(file, json_data, py_data)
    if node._data == 0xFFFFFFFF:
        node._data = 0


def StreamPage(node: Node, file, json_data, py_data):
    index = node._index
    page_size = int(node._root.PageSize)
    size = int(node._parent._parent.StreamSizes[index])

    stream_pages = pages(size, page_size)
    node.decrypt(file, ["*u4"] * stream_pages, py_data)


def Stream(node: Node, file, json_data, py_data):
    index = node._index
    page_size = int(node._root.PageSize)

    page_list = node._root.RootStream.StreamPages[index]

    if len(page_list._data) > 0:
        datas = []
        for page in page_list._data:
            file.seek(int(page) * page_size)
            datas.append(file.read(page_size))
        data = b''.join(datas)

        start = int(page_list._data[0]) * page_size
        if index == 1:
            node.decrypt(File(data, start), json_data['-Stream1'], py_data)
        else:
            node.decrypt_raw(File(data, start), start, len(data))
        # node.decrypt(File(data, int(node._root.RootStream.StreamPages._data[0]) * page_size), json_data, py_data)


def NamesSize(node: Node, file, json_data, py_data):
    node.decrypt(file, json_data, py_data)

    tell = file.tell()
    raw = file.read(int(node))
    file.seek(tell)
    cnt = raw.count(b'\0')
    node._parent["Names"] = Node(key='Names').decrypt(file, ["*s0"] * cnt, py_data)
