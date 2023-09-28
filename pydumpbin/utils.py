import sys

BYTE_ORDER = {
    '*': sys.byteorder,
    '+': 'big',
    '-': 'little',
}


def get_null_string(data, offset):
    idx = data.find(b'\0', offset)
    return bytes.decode(data[offset: idx])


def fread(file, size):
    data = file.read(size)
    if len(data) == 0:
        raise EOFError
    return data


def read_pad(file, opt, len):
    if len <= 0:
        res = []
        ch = fread(file, 1)
        while (ch.decode() == opt):
            res.append(ch)
            ch = fread(file, 1)
        file.seek(file.tell() - 1)
        return b''.join(res)


def read_string(file, opt, len):
    if len <= 0:
        res = []
        ch = fread(file, 1)
        while (ch != b'\0'):
            res.append(ch)
            ch = fread(file, 1)
        res = b''.join(res)
    else:
        res = fread(file, int(len))
    res = bytes.decode(res.strip(b'\0 '), errors="strict")
    if opt == 'i':
        res = int(res)

    return res


READ_BYTE = {
    'u': lambda f, o, x: int.from_bytes(fread(f, int(x)), BYTE_ORDER[o]),
    'i': lambda f, o, x: int.from_bytes(fread(f, int(x)), BYTE_ORDER[o], signed=True),
    's': lambda f, o, x: read_string(f, o, int(x)),
}


def read(file, form, initvars=None):
    if type(form) == str:
        types = form[1]
        len = int(form[2:])
        var = READ_BYTE[types](file, form[0], len) if types in READ_BYTE else read_pad(file, types, len)
    elif type(form) == type:
        var = form(file, initvars) if initvars else form(file)
    elif type(form) == list:
        var = []
        for v in form:
            try:
                var.append(read(file, v, initvars))
            except EOFError:
                pass
    return var


def from_bytes(obj, file, export):
    for k, v in export.items():
        var = read(file, v)
        setattr(obj, k, var)


def to_bytes(obj, export):
    res = b''
    for k, v in export.items():
        if hasattr(obj, k):
            value = getattr(obj, k)
            if type(v) == int:
                res = res + value.to_bytes(v, byteorder=sys.byteorder)
            elif type(v) == type:
                res = res + value.to_bytes()
    return res


def format_desc(value, desc):
    if type(desc) == dict:
        dict_desc = desc[value] if value in desc \
            else ' | '.join([desc[v] for v in desc.keys() if value & v])
        res = '{0:X} ({1})'.format(value, dict_desc) if len(dict_desc) > 0 else '{0:X}'.format(value)
    else:
        res = str(desc(value))
    return res


def format_obj(key, value, desc):
    if key in desc:
        res = format_desc(value, desc[key])
    elif type(value) == int:
        res = "{0:X}".format(value)
    elif type(value) == str:
        res = value
    elif type(value) == list:
        res = [format_obj(key, v, desc) for v in value]
    elif type(value) == tuple:
        res = str(value)
    elif type(value) == bytes:
        res = ' '.join(['%02X' % b for b in value])
    else:
        res = value.format()

    return res


def format(obj, keys, desc):
    res = {}
    for k in keys:
        value = getattr(obj, k)
        res[k] = format_obj(k, value, desc)

    return res


def read_bytes(file, offset, len):
    cur_offset = file.tell()
    data = file.read(len)
    file.seek(cur_offset)
    return data


def file_slice(file, begin, end=None):
    if file is None:
        return b''
    if end is None:
        end = file.tell()
    tell = file.tell()
    file.seek(begin)
    data = file.read(end - begin)
    file.seek(tell)
    return data


def hex(value):
    return "0x%04X" % value


def get_format(json_data, x64=True):
    platform = "-x64" if x64 is True else "-x86"
    return json_data[platform]
