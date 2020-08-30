from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
import binascii


# xor bytes objects into bytearray
def bytes_xor(a, b):
    ans = bytearray()
    for ai, bi in zip(a, b):
        ans.append(ai ^ bi)
    return ans


## cbc
# decrypts cbc
def decrypt_cbc(key, ct):
    # input
    key = binascii.unhexlify(key)
    ct = binascii.unhexlify(ct)

    # init
    print("Length: " + str(len(ct)))
    blocks = round(len(ct) / AES.block_size)
    pt = bytearray()
    aes = AES.new(key, AES.MODE_ECB)

    # decrypt
    for i in range(1, blocks):
        dec = aes.decrypt(ct[i * AES.block_size : (i + 1) * AES.block_size])
        iv = ct[(i - 1) * AES.block_size : i * AES.block_size]
        pt.extend(bytes_xor(dec, iv))

    # unpad
    pad_num = pt[len(pt) - 1]
    print("Pad Num: " + str(pad_num))
    pt = pt[ : len(pt) - pad_num]
    return pt.decode('ascii')


# checks with PyCrypto implementation
def check_decrypt_cbc(key, ct):
    # input
    key = binascii.unhexlify(key)
    ct = binascii.unhexlify(ct)

    # decrypt
    aes = AES.new(key, AES.MODE_CBC, ct[ : AES.block_size])
    pt = aes.decrypt(ct[AES.block_size : ])

    # unpad
    pad_num = pt[len(pt) - 1]
    pt = pt[: len(pt) - pad_num]
    return pt.decode('ascii')


# encrypts cbc
def encrypt_cbc(key, pt):
    # input, pad
    key = binascii.unhexlify(key)
    pt = pt.encode('ascii')
    pad_num = AES.block_size - (len(pt) % AES.block_size)
    pad_str = bytes([pad_num]) * pad_num
    pt += pad_str

    # init
    print("Length: " + str(len(pt)))
    blocks = round(len(pt) / AES.block_size)
    ct = bytearray()
    iv = Random.new().read(AES.block_size)
    civ = iv
    aes = AES.new(key, AES.MODE_ECB)

    # encrypt
    for i in range(0, blocks):
        if i > 0: civ = ct[(i - 1) * AES.block_size : i * AES.block_size]
        pre = bytes(bytes_xor(pt[i * AES.block_size : (i + 1) * AES.block_size], civ))
        enc = aes.encrypt(pre)
        ct.extend(enc)
    return binascii.hexlify(iv + ct)


# checks with PyCrypto implementation
def check_encrypt_cbc(key, pt):
    # input, pad
    key = binascii.unhexlify(key)
    pt = pt.encode('ascii')
    pad_num = AES.block_size - (len(pt) % AES.block_size)
    pad_str = bytes([pad_num]) * pad_num
    pt += pad_str

    # encrypt
    iv = Random.new().read(AES.block_size)
    aes = AES.new(key, AES.MODE_CBC, iv)
    ct = aes.encrypt(pt)
    return binascii.hexlify(iv + ct)


## ctr
# decrypts ctr
def decrypt_ctr(key, ct):
    # input
    key = binascii.unhexlify(key)
    ct = binascii.unhexlify(ct)

    # init
    print("Length: " + str(len(ct)))
    blocks = round(len(ct) / AES.block_size)
    pt = bytearray()
    aes = AES.new(key, AES.MODE_ECB)
    iv = int.from_bytes(ct[ : AES.block_size], 'big')

    # decrypt
    for i in range(1, blocks):
        dec = aes.encrypt(iv.to_bytes(AES.block_size, 'big'))
        pt.extend(bytes_xor(dec, ct[i * AES.block_size : (i + 1) * AES.block_size]))
        iv += 1
    return pt.decode('ascii')


# checks with PyCrypto implementation
def check_decrypt_ctr(key, ct):
    # input
    key = binascii.unhexlify(key)
    ct = binascii.unhexlify(ct)

    # decrypt
    ctr = Counter.new(AES.block_size * 8, initial_value = int.from_bytes(ct[ : AES.block_size], 'big'))
    aes = AES.new(key, AES.MODE_CTR, counter = ctr)
    pt = aes.decrypt(ct[AES.block_size : ])
    return pt.decode('ascii')


# encrypts ctr
def encrypt_ctr(key, pt):
    # input
    key = binascii.unhexlify(key)
    pt = pt.encode('ascii')

    # init
    print("Length: " + str(len(pt)))
    blocks = round(len(pt) / AES.block_size)
    ct = bytearray()
    aes = AES.new(key, AES.MODE_ECB)
    iv = Random.new().read(AES.block_size)
    civ = int.from_bytes(iv, 'big')

    # encrypt
    for i in range(0, blocks):
        enc = aes.encrypt(civ.to_bytes(AES.block_size, 'big'))
        ct.extend(bytes_xor(enc, pt[i * AES.block_size : (i + 1) * AES.block_size]))
        civ += 1
    return binascii.hexlify(iv + ct)


# checks with PyCrypto implementation
def check_encrypt_ctr(key, pt):
    # input
    key = binascii.unhexlify(key)
    pt = pt.encode('ascii')

    # encrypt
    iv = Random.new().read(AES.block_size)
    ctr = Counter.new(AES.block_size * 8, initial_value = int.from_bytes(iv, 'big'))
    aes = AES.new(key, AES.MODE_CTR, counter = ctr)
    ct = aes.encrypt(pt)
    return binascii.hexlify(iv + ct)

# key = input('Key: ')
# ct = input('Ciphertext: ')

# test decrypt cbc
print('Testing CBC decryption')
keys = ['140b41b22a29beb4061bda66b6747e14', '140b41b22a29beb4061bda66b6747e14']
cts = ['4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81',
      '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253']
for key, ct in zip(keys, cts):
    print('Plaintext: ' + decrypt_cbc(key, ct))
    print('Check: ' + check_decrypt_cbc(key, ct))
    print()

# test encrypt cbc
print('Testing CBC encryption')
pts = ['Basic CBC mode encryption needs padding.',
       'Our implementation uses rand. IV']
for key, pt in zip(keys, pts):
    print('Plaintext: ' + decrypt_cbc(key, encrypt_cbc(key, pt)))
    print('Check: ' + decrypt_cbc(key, check_encrypt_cbc(key, pt)))
    print()

# test decrypt cbc
print('Testing CTR decryption')
keys = ['36f18357be4dbd77f050515c73fcf9f2', '36f18357be4dbd77f050515c73fcf9f2']
cts = ['69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329',
      '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451']
for key, ct in zip(keys, cts):
    print('Plaintext: ' + decrypt_ctr(key, ct))
    print('Check: ' + check_decrypt_ctr(key, ct))
    print()

# test encrypt ctr
print('Testing CTR encryption')
pts = ['CTR mode lets you build a stream cipher from a block cipher.',
       'Always avoid the two time pad!']
for key, pt in zip(keys, pts):
    print('Plaintext: ' + decrypt_ctr(key, encrypt_ctr(key, pt)))
    print('Check: ' + decrypt_ctr(key, check_encrypt_ctr(key, pt)))
    print()
