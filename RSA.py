import random


def primesInRange(x, y):
    prime_list = []
    for n in range(x, y):
        isPrime = True

        for num in range(2, n):
            if n % num == 0:
                isPrime = False

        if isPrime:
            prime_list.append(n)
    return prime_list


def computeGCD(x, y):
    while y:
        x, y = y, x % y
    return x


def modInverse(e, z):
    for x in range(1, z):
        if ((e % z) * (x % z)) % z == 1:
            return x
    return -1


def relativelyPrimesInRange(z):
    prime_list = []
    for n in range(2, z):
        isPrime = True
        if computeGCD(n, z) != 1:
            isPrime = False
        if isPrime:
            prime_list.append(n)
    return prime_list


def rsa_key_generation():
    global private_key
    global public_key
    global n
    global z
    global e
    global d
    p = random.choice(primesInRange(3, 50))
    q = random.choice(primesInRange(3, 50))
    while p == q or p * q > 255:
        q = random.choice(primesInRange(3, 50))
    n = p * q
    z = (p - 1) * (q - 1)
    e = random.choice(relativelyPrimesInRange(z))
    d = modInverse(e, z)
    return n,e,d


def encryptSymmetric(arr):
    encryptedList = []

    for byte in arr:
        encryptedList.append(pow(int(chr(byte), 16), e) % n)
    return encryptedList, n, d


def decryptSymmetric(arr, d):
    decryptedList = []
    for byte in arr:
        decryptedList.append(hex(pow(byte, d) % n))
    return decryptedList
