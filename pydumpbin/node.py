import os
import json
import runpy
import datetime
import capstone

from .utils import read, file_slice, hex, get_format


def read_py(f, path):
    if not os.path.exists(path):
        return 'failed', {}
    py_data = runpy.run_path(path)
    if not check_ext(f, py_data):
        return 'invalid', {}
    if not check_magic(f, py_data):
        return 'invalid', {}
    return 'success', py_data


def process_file(f, path, check=False):
    py_path = path.replace('.json', '.py')
    state, py_data = read_py(f, py_path)
    if state == 'invalid':
        return state, None, None

    with open(path, 'r') as jf:
        json_data = json.load(jf)

    return 'success', json_data, py_data


def check_magic(f, py_data):
    if "MAGIC" not in py_data:
        return True
    magic_data = py_data["MAGIC"]
    if type(magic_data) is bytes:
        return magic_data == f.read(len(magic_data))
    return magic_data(f)


def check_ext(f, py_data):
    if "EXT" not in py_data:
        return True
    ext = os.path.splitext(f.name)[1]
    if ext in py_data["EXT"]:
        return True
    return False


def get_obj(raw_key, tab):
    key = raw_key[1:]
    return tab[key]


def generate_list(raw, format, parent, root):
    key = raw[1:-1]
    if key.startswith('.'):
        key = key[1:]
        tab = parent._parent
    else:
        tab = root
    values = key.split('.')
    for value in values:
        tab = tab[value]
    return [format] * int(tab)


class Node:
    def __init__(self, key='', root=None, parent=None, data=None):
        self._py = False
        self._addr = ''
        self._desc = ''
        self._display = ''
        self._key = key
        self._parent = parent
        self._data = data if data is not None else {}
        self._root = root if root is not None else self

    def __getitem__(self, i):
        return self._data[i]

    def __setitem__(self, i, node):
        if type(node) is Node:
            self._data[i] = node

        if not i.startswith('+'):
            setattr(self, i, node)

    def __lt__(self, other):
        return self._data < other

    def __gt__(self, other):
        return self._data > other

    def __eq__(self, other):
        if type(other) is str:
            return self._desc == other
        return self._data == other

    def __int__(self):
        return self._data

    def __bool__(self):
        return self._data

    def desc(self, json_data):
        if json_data == 'timestamp':
            self._desc = datetime.datetime.fromtimestamp(self._data) if self._data > 0 else 'FFFFFFFF'
        elif type(json_data) is dict:
            desc = {eval(k) if type(k) is str else k: v for k, v in json_data.items()}
            keys = sorted(desc, reverse=True)
            value = self._data
            if value in desc:
                self._desc = desc[value]
            else:
                self._desc = []
                for k in keys:
                    if value >= k and value & k:
                        self._desc.append(desc[k])
                        value -= k

    def decrypt(self, f, json_data, py_data):
        self._begin = f.tell() if f else 0
        self._addr = hex(self._begin)
        self._format = json_data
        if self._py or not self.decrypt_py(f, json_data, py_data):
            self.decrypt_json(f, json_data, py_data)
        if not hasattr(self, '_raw'):
            self._raw = file_slice(f, self._begin)
        return self

    def decrypt_with_platform(self, file, json_data, py_data, x64=None):
        self.decrypt(file, get_format(json_data, x64), py_data)
        return self

    def decrypt_with_offset(self, f, json_data, py_data, offset):
        tell = f.tell()
        f.seek(offset)
        self.decrypt(f, json_data, py_data)
        f.seek(tell)
        return self

    def decrypt_raw(self, f, begin, size):
        self._begin = begin
        self._addr = hex(self._begin)

        self._raw = file_slice(f, self._begin, begin + size)
        return self

    def decrypt_assembly(self, f, begin, size):
        self._begin = begin
        self._addr = hex(self._begin)

        self._raw = file_slice(f, self._begin, begin + size)
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        for v in md.disasm(self._raw, 0x0):
            k = "0x%X" % v.address
            self._data[k] = Node(data='%s\t%s' % (v.mnemonic, v.op_str))
            self._data[k]._begin = begin + v.address
            self._data[k]._raw = v.bytes

        return self

    def decrypt_json(self, f, json_data, py_data):
        if json_data is None:
            return
        if type(json_data) is str:
            self.decrypt_str(f, json_data, py_data)
        if type(json_data) is dict:
            self.decrypt_dict(f, json_data, py_data)
        if type(json_data) is list:
            self.decrypt_list(f, json_data, py_data)

    def decrypt_py(self, f, json_data, py_data):
        if self._key in py_data and callable(py_data[self._key]):
            self._py = True
            return py_data[self._key](self, f, json_data, py_data) is not False

    def decrypt_file(self, f, json_name):
        path = os.path.join(os.path.dirname(__file__), 'template', json_name)
        state, json_data, py_data = process_file(f, path)
        if state != 'success':
            return False

        if py_data and '__init__' in py_data:
            py_data['__init__'](self, f, json_data, py_data)

        self.decrypt(f, json_data, py_data)

        if py_data and '__del__' in py_data:
            py_data['__del__'](self, f, json_data, py_data)

        return True

    def decrypt_str(self, f, json_data: str, py_data):
        if json_data.endswith('.json'):
            self.decrypt_file(f, json_data)
        else:
            try:
                self._data = read(f, json_data)
            except Exception:
                pass

    def decrypt_dict(self, f, json_data: dict, py_data):
        for k, v in json_data.items():

            kargs = {
                'parent': self,
                'root': self._root
            }

            assert not k.startswith('$')

            if k.startswith('-') or k.startswith('>'):
                continue
            elif k.startswith('?'):
                value = get_obj(k, self._data)
                value.desc(v)
            elif k.startswith('['):
                format = generate_list(k, v, **kargs)
                self.decrypt_list(f, format, py_data)
            else:
                self[k] = Node(k, **kargs).decrypt(f, v, py_data)

    def decrypt_list(self, f, json_data, py_data):
        k = self._key[:-1]  # remove 's'
        self._data = [Node(k, root=self._root, parent=self).decrypt(f, format, py_data)
                      for format in json_data]

    def get(self):
        if self._display != '':
            return self._display
        if type(self._data) is int:
            return hex(self._data)
        return self._data

    def to_data(self):
        data = self.get()
        if type(data) is dict:
            return {k: v.to_data() for k, v in data.items()}
        else:
            return data

    def to_hex(self):
        return ['%02X' % x for x in self._raw]

    def to_display(self):
        return [chr(x) if 32 <= x and x <= 126 else '.' for x in self._raw]


def parse_from_template(file):
    for root, dirs, files in os.walk(os.path.join(os.path.dirname(__file__), 'template')):
        for json_name in files:
            if not json_name.endswith('json') or root.endswith('header'):
                continue
            file.seek(0)
            node = Node()
            if node.decrypt_file(file, os.path.join(root, json_name)):
                return node
