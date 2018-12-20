import ctypes
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


def uleb128(_bytes, offset=0x0):
    p = _bytes[offset]
    start = offset
    result = 0
    bit = 0
    while True:
        slice = p & 0x7f

        if bit >= 64 or slice << bit >> bit != slice:
            log_error("ULEB128 Error!")
            break
        else:
            result |= (slice << bit)
            bit += 7

        if (p & 0x80 == 0):
            break
        offset += 1
        p = _bytes[offset]
    result = ctypes.c_int64(result).value
    return (result, offset - start)
    

