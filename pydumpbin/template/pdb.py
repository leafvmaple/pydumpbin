import pdbparse

from pydumpbin.node import Node

MAGIC = b'Microsoft'


def __init__(node: Node, file, json_data, py_data):
    file.seek(0)
    pdb = pdbparse.PDB7(file, True)
    print(pdb)
    file.seek(0)
