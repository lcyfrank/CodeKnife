# Inner Function
def parse_int(_bytes):
    temp_bytes = b''
    for i in range(len(_bytes)):
        temp_bytes = _bytes[i: i + 1] + temp_bytes
    return int(temp_bytes.hex(), 16)


def parse_str(_bytes):
    return _bytes.decode('utf-8')
