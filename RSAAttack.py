import gmpy2, binascii


# abs(p - q) < 2N^(1/4)
def attack1(N):
    root = gmpy2.iroot_rem(N, 2)
    A = root[0]
    if root[1] > 0:
        A += 1 # ceiling

    x = gmpy2.iroot(A * A - N, 2)[0]
    return A - x


# abs(p - q) < 2^11*N^(1/4)
def attack2(N):
    root = gmpy2.iroot_rem(N, 2)
    Amin = root[0]
    if root[1] > 0:
        Amin += 1  # ceiling

    Amax = min((N+1)/2, Amin + 2 ** 20)

    A = Amin
    while A <= Amax:
        # print('Searching ' + str(A))
        x = gmpy2.iroot(A * A - N, 2)[0]
        if (A - x) * (A + x) == N:
            return A - x
        A += 1
    return 'Not found'


# abs(3p - 2q) < N^(1/4)
def attack3(N):
    root = gmpy2.iroot_rem(24 * N, 2)
    A = root[0]
    if root[1] > 0:
        A += 1  # ceiling

    x = gmpy2.isqrt(A * A - 24 * N)
    # print(N)
    # print((A + x) * (A - x) // 24)
    if (A - x) % 6 == 0 and (A + x) % 4 == 0:
        return min((A - x) // 6, (A + x) // 4)
    return min((A - x) // 4, (A + x) // 6)



# same constraint on N as attack1
def decryptRSA(e, ct, N):
    # factor
    root = gmpy2.iroot_rem(N, 2)
    A = root[0]
    if root[1] > 0:
        A += 1  # ceiling
    x = gmpy2.iroot(A * A - N, 2)[0]
    p = A - x
    q = A + x

    # decrypt
    phi = (p - 1) * (q - 1)
    d = gmpy2.invert(e, phi)
    unpad = gmpy2.powmod(ct, d, N).digits(16)
    if len(unpad) & 1:
        unpad = '0' + unpad # pad with 0
    pkcs1 = binascii.unhexlify(unpad)
    print(binascii.hexlify(pkcs1))

    # extract
    sep = 0x00
    return pkcs1[pkcs1.find(sep)+1:].decode('ascii')

challenges = [
    '17976931348623159077293051907890247336179769789423065727343008115 \
    77326758055056206869853794492129829595855013875371640157101398586 \
    47833778606925583497541085196591615128057575940752635007475935288 \
    71082364994994077189561705436114947486504671101510156394068052754 \
    0071584560878577663743040086340742855278549092581',

    '6484558428080716696628242653467722787263437207069762630604390703787 \
    9730861808111646271401527606141756919558732184025452065542490671989 \
    2428844841839353281972988531310511738648965962582821502504990264452 \
    1008852816733037111422964210278402893076574586452336833570778346897 \
    15838646088239640236866252211790085787877',

    '72006226374735042527956443552558373833808445147399984182665305798191 \
    63556901883377904234086641876639384851752649940178970835240791356868 \
    77441155132015188279331812309091996246361896836573643119174094961348 \
    52463970788523879939683923036467667022162701835329944324119217381272 \
    9276147530748597302192751375739387929']
e = 65537
ct = '22096451867410381776306561134883418017410069787892831071731839143676\
    135600120538004282329650473509424343946219751512256465839967942889460\
    764542040581564748988013734864120452325229320176487916666402997509188\
    729971690526083222067771600019329260870009579993724077458967773697817\
    571267229951148662959627934791540'

print('Challenge 1')
print(attack1(gmpy2.mpz(challenges[0])))
print('Challenge 2')
print(attack2(gmpy2.mpz(challenges[1])))
print('Challenge 3')
print(attack3(gmpy2.mpz(challenges[2])))
print('Decrypt RSA')
print(decryptRSA(e, gmpy2.mpz(ct), gmpy2.mpz(challenges[0])))