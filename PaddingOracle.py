import urllib3
import binascii
http = urllib3.PoolManager()

block_size = 16

target_url = 'http://crypto-class.appspot.com/po?er='


def query(q):
    req = http.request('GET', target_url + q)
    return req.status


# xor bytearray objects
def bytes_xor(a, b):
    ans = bytearray()
    for ai, bi in zip(a, b):
        ans.append(ai ^ bi)
    return ans


def padding_oracle(ct):
    ct = bytearray(binascii.unhexlify(ct))
    pt = bytearray()

    num_blocks = round(len(ct) / block_size)
    for b in range(1, num_blocks):
        pt_block = bytearray()
        for l in range(1, block_size + 1):
            print('block %d, byte %d' % (b, l))
            alt = -1
            found = False
            for g in range(0, 256):
                # print(g)

                # construct guess
                guess = bytearray([g]) + pt_block[:]
                # print(binascii.hexlify(guess))

                # construct query, xoring ct, pad, guess
                ctq = ct[:]
                pad = bytearray([l]) * l
                # print(binascii.hexlify(pad))
                ctq[-(block_size + l): -block_size] = bytes_xor(ctq[-(block_size + l): -block_size], bytes_xor(pad, guess))

                # do query
                # print(str(binascii.hexlify(ctq).decode('ascii')))
                q = query(str(binascii.hexlify(ctq).decode('ascii')))
                if q == 404:
                    pt_block = guess
                    found = True
                    print('FOUND with g = %d' % g)
                    break
                elif q == 200:
                    alt = guess
            if not found:
                if alt != -1:
                    print('USING ALT')
                    pt_block = alt
                else:
                    print('NOT FOUND')
                    return
        pt = pt_block + pt
        ct = ct[: -block_size]
    return pt.decode('ascii')


ct1 = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'
# ct2 = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0'
print(padding_oracle(ct1))