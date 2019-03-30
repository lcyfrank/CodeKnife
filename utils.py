import ctypes
import hashlib
import sys

# Inner Function
def parse_int(_bytes, little_end=True):
    if not little_end:
        return int(_bytes.hex(), 16)
    temp_bytes = b''
    for i in range(len(_bytes)):
        temp_bytes = _bytes[i: i + 1] + temp_bytes
    return int(temp_bytes.hex(), 16)


def parse_str(_bytes):

    try:
        string = _bytes.decode('utf-8')
        string = string.replace('\x00', '')
        return string
    except UnicodeDecodeError as e:
        # print(e)
        string = _bytes.hex()
        string_list = []
        for i in range(int(len(string) / 2)):
            string_list.append(string[i * 2: i * 2 + 2])
        string = ""
        for element in string_list:
            string += ("\\x" + element)
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


def sorted_list_for_hex_string(l):
    def convert_to_int(s):
        return int(s, 16)

    def convert_to_str(i):
        return hex(i)
    # before = datetime.now()
    l = list(map(convert_to_int, l))
    # after = datetime.now()
    # print((after - before).microseconds)

    # before = datetime.now()
    l.sort()
    # after = datetime.now()
    # print((after - before).microseconds)

    # before = datetime.now()
    l = list(map(convert_to_str, l))
    # after = datetime.now()
    # print((after - before).microseconds)
    return l

def md5_for_file(file_path):
    hash_code = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
    print(hash_code)
