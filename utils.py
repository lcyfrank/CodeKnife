# Inner Function
def parse_int(_bytes):
    temp_bytes = b''
    for i in range(len(_bytes)):
        temp_bytes = _bytes[i: i + 1] + temp_bytes
    return int(temp_bytes.hex(), 16)


def parse_str(_bytes):
    string = _bytes.decode('utf-8')
    string = string.replace('\x00', '')
    return string

def log_error(error):
    print("[Error] %s" % (error))