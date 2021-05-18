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
    for x, y in zip(generated_mac, incoming_mac):
        result |= ord(x) ^ ord(y)
    return result


def signature(data, keyForAES, keyForHMAC, name, image):
    global enc
    encryptedKeyForHMAC, n, d = encryptSymmetric(
        np.fromstring(keyForHMAC, dtype=np.uint8))                                                                      # RSA encryption for symmetric key
    enc = EncryptAES(data, keyForAES, AES.MODE_CBC, name, image)                                                        # AES decryption for image
    keyForHMAC = ''.join(map(str, str(keyForHMAC).replace("0x", "").replace("[", "")                                    # hexadecimal formatting
                             .replace("'", "").replace(",", "").replace(" ", "").replace("]", "")))
    sign = hmac.new(
        bytearray.fromhex(keyForHMAC),                                                                                  #creates digital signature with sha256 mod
        msg=enc,
        digestmod=hashlib.sha256
    ).hexdigest()
    return sign, encryptedKeyForHMAC, d                                                                                 #returns digital signature, K+, d


def decrypt(keyForAES, keyForHMAC, n, d, name, image, signature):
    keyForHMAC = decryptSymmetric(keyForHMAC, d)                                                                        #Decrypts key with d

    keyForHMAC = ''.join(map(str, str(keyForHMAC).replace("0x", "").replace("[", "").replace("'", "")
                             .replace(",", "").replace(" ", "").replace("]", "")))
    if compare(hmac.new(
            bytearray.fromhex(keyForHMAC),
            msg=enc,                                                                                                    #generates signature with decrypted key and checks whether
            digestmod=hashlib.sha256                                                                                    #generated digital signature and incoming digital signature are same
    ).hexdigest(), signature):
        print("MAC's don't match")
        return
    dec = DecryptAES(enc, keyForAES, AES.MODE_CBC, name, image)                                                         #if authentication was provided then decrypts encrypted image file
