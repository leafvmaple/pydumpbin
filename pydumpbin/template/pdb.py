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


def StreamPage(node: Node, file, json_data, py_data):
    page_size = int(node._root.PageSize)
    index = node._index
    size = int(node._parent._parent.StreamSizes[index])

    stream_pages = pages(size, page_size)
    node.decrypt(file, ["*u4"] * stream_pages, py_data)
