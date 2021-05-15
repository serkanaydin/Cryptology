import hmac
import hashlib
from multiprocessing.context import AuthenticationError

import numpy as np
from Crypto import Random
from aes import *
from RSA import *

enc = []
nonce = Random.get_random_bytes(8)


def compare(incoming_mac, generated_mac):
    if len(incoming_mac) != len(generated_mac):
        print("Sizes don't match")
        return False
    result = 0
    for x, y in zip(generated_mac,incoming_mac):
        result |= ord(x) ^ ord(y)
    return result


def signature(data, keyForAES, keyForHMAC, name, image):
    global enc
    encryptedKeyForHMAC, n, d = encryptSymmetric(np.fromstring(keyForHMAC, dtype=np.uint8))
    print("hmac enc")
    print(keyForHMAC)
    enc = EncryptAES(data, keyForAES, AES.MODE_CBC, name, image)
    keyForHMAC = ''.join(map(str, str(keyForHMAC).replace("0x", "").replace("[", "").replace("'", "").replace(",",
                                                                                                              "").replace(" ", "").replace("]", "")))
    sign = hmac.new(
        bytearray.fromhex(keyForHMAC),
        msg=enc,
        digestmod=hashlib.sha256
    ).hexdigest().upper()
    return sign, encryptedKeyForHMAC, d


def decrypt(data, keyForAES, keyForHMAC, n, d, name, image, signature):
    keyForHMAC = decryptSymmetric(keyForHMAC, d)



    keyForHMAC = ''.join(map(str, str(keyForHMAC).replace("0x", "").replace("[","").replace("'","").replace(",","").replace(" ","").replace("]","")))

    print("hmac")
    print(keyForHMAC)
    print(keyForHMAC.__getitem__(255))
    if compare(hmac.new(
            bytearray.fromhex(keyForHMAC),
            msg=enc,
            digestmod=hashlib.sha256
    ).hexdigest().upper(), signature):
        print("MAC's don't match")
        return
    dec = DecryptAES(enc, keyForAES, AES.MODE_CBC, name, image)
