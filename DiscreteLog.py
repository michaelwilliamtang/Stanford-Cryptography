import gmpy2


def dlog(p, g, h):
    B = 2 ** 20

    # hash all possible h / g^x1
    lhs = {}
    for x1 in range(B + 1):
        try:
            lhs[gmpy2.divm(h, gmpy2.powmod(g, x1, p), p)] = x1
            print('Adding x1 %d' % x1)
        except:
            print('Skipping x1 %d' % x1)

    # test all possible g^(B * x0)
    gB = gmpy2.powmod(g, B, p)
    for x0 in range(B + 1):
        rhs = gmpy2.powmod(gB, x0, p)
        print('Trying x0 %d' % x0)
        if rhs in lhs.keys():
            x1 = lhs[rhs]
            print('Found x1 %d' % x1)
            return x0 * B + x1

    print('Not found')
    return -1


p = '134078079299425970995740249982058461274793658205923933 \
    77723561443721764030073546976801874298166903427690031 \
    858186486050853753882811946569946433649006084171'
g = '11717829880366207009516117596335367088558084999998952205 \
    59997945906392949973658374667057217647146031292859482967 \
    5428279466566527115212748467589894601965568'
h = '323947510405045044356526437872806578864909752095244 \
    952783479245297198197614329255807385693795855318053 \
    2878928001494706097394108577585732452307673444020333'

p = gmpy2.mpz(p)
g = gmpy2.mpz(g)
h = gmpy2.mpz(h)

x = dlog(p, g, h)
print(x)
print('verifying: h == %d' % gmpy2.powmod(g, x, p))