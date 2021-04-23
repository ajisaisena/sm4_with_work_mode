from SM4 import *
import binascii


def hex_xor(a, b):
    """
    32位16进制字符串的异或
    :param a:字符串a
    :param b: 字符串b
    :return: 32位字符串异或结果
    """
    bin_a = '{:0128b}'.format(int(a, 16))
    bin_b = '{:0128b}'.format(int(b, 16))
    bin_res = xor(bin_a, bin_b)
    hex_res = '{:032X}'.format(int(bin_res, 2))
    return hex_res


def padding(text, block_size=16, is_encrypt=True):
    """
    PKCS #7 填充
    :param text: 写入文本
    :param block_size: 分块长度
    :param is_encrypt: 是否为加密
    :return: 返回填充或解填充的结果
    """
    if is_encrypt:
        num = block_size - len(text) % block_size
        pad = (chr(num).encode('utf-8') * num)
        return text + pad
    else:
        if len(text) % 16 != 0:
            exit("The padding result is wrong. Check whether the padding is correct.")
        num = int(text[-2:], 16)
        return text[:(len(text) - num * 2)]


def ecb(file_name, block_size=16, key='0123456789abcdeffedcba9876543210', is_encrypt=True):
    """
    ecb加解密工作模式
    :param file_name:文件名称
    :param block_size: 分组大小
    :param key: 密钥
    :param is_encrypt:是否加密
    :return: ecb加解密字符串
    """
    result = ''
    with open(file_name, 'rb') as file:
        text_byte = file.read()
    if is_encrypt:
        text_byte = padding(text_byte, is_encrypt=is_encrypt)
    lens = len(text_byte)
    for i in range(lens // block_size):
        temp = text_byte[block_size * i:block_size * (i + 1)]
        result += SM4(temp.hex(), key, is_encrypt)
    if not is_encrypt:
        result = padding(result, is_encrypt=is_encrypt)
    return result


def cbc(file_name, block_size=16, IV='0123456789abcdeffedcba9876543210', key='0123456789abcdeffedcba9876543210'):
    """
    cbc加密工作模式
    :param file_name:文件名称
    :param block_size: 块大小
    :param IV: 初始向量
    :param key: 密钥
    :return: cbc加密字符串
    """
    result = ''
    with open(file_name, 'rb') as file:
        text_byte = file.read()
    text_byte = padding(text_byte)
    lens = len(text_byte)
    string_xor = IV
    for i in range(lens // block_size):
        temp = text_byte[block_size * i:block_size * (i + 1)]
        temp = temp.hex()
        hex_input = hex_xor(temp, string_xor)
        out = SM4(hex_input, key)
        result += out
        string_xor = out
    return result


def cbc_de(file_name, block_size=16, IV='0123456789abcdeffedcba9876543210', key='0123456789abcdeffedcba9876543210'):
    """
    cbc解密工作模式
    :param file_name:文件名称
    :param block_size: 块大小
    :param IV: 初始向量
    :param key: 密钥
    :return: cbc解密后字符串
    """
    result = ''
    with open(file_name, 'rb') as file:
        text_byte = file.read()
    lens = len(text_byte)
    string_xor = IV
    for i in range(lens // block_size):
        temp = text_byte[block_size * i:block_size * (i + 1)]
        temp = temp.hex()
        out = SM4(temp, key, False)
        result += hex_xor(out, string_xor)
        string_xor = temp
    result = padding(result, is_encrypt=False)
    return result


def ctr(file_name, block_size=16, IV='0123456789abcdeffedcba9876543210', key='0123456789abcdeffedcba9876543210'):
    """
    ctr 工作模式
    :param file_name: 文件名称
    :param block_size: 块大小
    :param IV: 初始向量
    :param key: 密钥
    :return: ctr加解密后字符串
    """
    result = ''
    with open(file_name, 'rb') as file:
        text_byte = file.read()
    rounds = len(text_byte) // block_size
    counter = IV
    for i in range(rounds):
        temp = text_byte[block_size * i:block_size * (i + 1)]
        temp = temp.hex()
        out = SM4(counter, key)
        result += hex_xor(temp, out)
        counter = '{:032X}'.format(int(counter, 16) + 0x01)
    if len(text_byte) // block_size != 0:
        temp = text_byte[block_size * rounds:]
        temp = temp.hex()
        out = SM4(counter, key)
        out = out[:len(temp)]
        res = '%X' % (int(temp, 16) ^ int(out, 16))
        while len(res) < len(temp):
            res = '0' + res
        result += res
    return result


def cfb(file_name, block_size=32, IV='0123456789abcdeffedcba9876543210', key='0123456789abcdeffedcba9876543210',
        is_encode=True):
    """
    cfb 工作模式
    :param file_name: 文件名称
    :param block_size: 块大小
    :param IV: 初始向量
    :param key: 密钥
    :param is_encode:是否加密
    :return: cfb工作后结果
    """
    result = ''
    text_byte = ''
    with open(file_name, 'rb') as file:
        text_byte = file.read()
    rounds = len(text_byte) * 2 // block_size
    string_input = IV
    text = text_byte.hex()
    for i in range(rounds):
        temp = text[block_size * i:block_size * (i + 1)]
        out = SM4(string_input, key)
        out = out[:block_size]
        res = '%X' % (int(temp, 16) ^ int(out, 16))
        while len(res) < len(temp):
            res = '0' + res
        result += res
        if is_encode:
            string_input = string_input[:-block_size] + res
        else:
            string_input = string_input[:-block_size] + temp
    if len(text_byte) % block_size != 0:
        temp = text[block_size * rounds:]
        out = SM4(string_input, key)
        out = out[:len(temp)]
        res = '%X' % (int(temp, 16) ^ int(out, 16))
        while len(res) < len(temp):
            res = '0' + res
        result += res
    return result


def ofb(file_name, block_size=32, IV='0123456789abcdeffedcba9876543210', key='0123456789abcdeffedcba9876543210'):
    """
    ofb 工作模式
    :param file_name:文件名称
    :param block_size: 块大小
    :param IV: 初始向量
    :param key: 密钥
    :return: ofb加解密后结果
    """
    result = ''
    with open(file_name, 'rb') as file:
        text_byte = file.read()
    rounds = len(text_byte) * 2 // block_size
    string_input = IV
    text = text_byte.hex()
    for i in range(rounds):
        temp = text[block_size * i:block_size * (i + 1)]
        out = SM4(string_input, key)
        string_input = out
        out = out[:block_size]
        res = '%X' % (int(temp, 16) ^ int(out, 16))
        while len(res) < len(temp):
            res = '0' + res
        result += res
    if len(text_byte) % block_size != 0:
        temp = text[block_size * rounds:]
        out = SM4(string_input, key)
        out = out[:len(temp)]
        res = '%X' % (int(temp, 16) ^ int(out, 16))
        while len(res) < len(temp):
            res = '0' + res
        result += res
    return result


def write_file(filename, text):
    with open(filename, 'wb') as f:
        f.write(binascii.a2b_hex(text.encode('utf-8')))
    f.close()


def main():
    write_file('my_ecb', ecb('message'))
    write_file('my_mes_ecb', ecb('cipher-ecb', is_encrypt=False))
    write_file('my_cbc', cbc('message'))
    write_file('my_mes_cbc', cbc_de('cipher-cbc'))
    write_file('my_ctr', ctr('message'))
    write_file('my_mes_ctr', ctr('cipher-ctr'))
    write_file('my_cfb', cfb('message'))
    write_file('my_mes_cfb', cfb('cipher-cfb', is_encode=False))
    write_file('my_ofb', ofb('message'))
    write_file('my_mes_ctr', ofb('cipher-ofb'))


if __name__ == '__main__':
    main()
