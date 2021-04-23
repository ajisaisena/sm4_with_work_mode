from SM4_table import *



def left_shift(string, num):
    return string[num:] + string[:num]


def xor(a, b):  
    result = ""
    for i in range(len(a)):
        temp = int(a[i], 2) ^ int(b[i], 2)
        if temp == 1:
            result += '1'
        else:
            result += '0'
    return result


def fn_l(text):
    return xor(xor(xor(xor(text, left_shift(text, 2)), left_shift(text, 10)), left_shift(text, 18)),
               left_shift(text, 24))


def t(text):
    return fn_l(s(text))


def s(text):
    sub_array = []
    for i in range(4):
        sub_array.append(text[8 * i:8 * (i + 1)])
    result = ''
    for num in sub_array:
        row = int(num[:4], 2)
        col = int(num[4:], 2)
        result += '{:08b}'.format(SM4_SBOX[row * 16 + col])
    return result


def l_quote(sub_key):
    return xor(xor(sub_key, left_shift(sub_key, 13)), left_shift(sub_key, 23))


def t_quote(sub_key):
    return l_quote(s(sub_key))


def generate_key(key):
    k = []
    for i in range(4):
        k.append(xor(key[32 * i:32 * (i + 1)], '{:032b}'.format(SM4_FK[i])))
    for i in range(32):
        rk = xor(k[i], t_quote(
            xor(xor(xor(k[i + 1], k[i + 2]), k[i + 3]), '{:032b}'.format(SM4_CK[i]))))
        k.append(rk)

    return k[4:]


def SM4(plain, key, is_encode=True):
    x = []
    plain_bin = '{:0128b}'.format(int(plain, 16))
    key_bin = '{:0128b}'.format(int(key, 16))
    result = ''
    for i in range(4):
        x.append(plain_bin[32 * i:32 * (i + 1)])
    round_keys = generate_key(key_bin)
    if not is_encode:
        round_keys.reverse()
    for i in range(32):
        x.append(
            xor(x[i], t(xor(xor(xor(x[i + 1], x[i + 2]), x[i + 3]), round_keys[i]))))
    for i in range(35, 31, -1):
        result += x[i]
    result = '{:032X}'.format(int(result, 2))
    return result


def main():
    print(SM4('0123456789abcdeffedcba9876543210',
              '0123456789abcdeffedcba9876543210'))


if __name__ == '__main__':
    main()
