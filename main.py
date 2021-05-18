import sys

sys.path.append(".")
import numpy as np
from RSA import *
from aes import *
from HMAC import *
from timeit import default_timer as timer

encrypted = []
decrypted = []
private_key = ""
public_key = ""
e: int
n: int
z: int
d: int
iv: bytes
n, z, e, d = 0, 0, 0, 0

back = Image.open('background.jpg')
data = back.convert("RGB").tobytes()

n, e, d = rsa_key_generation()                                                                                          #RSA public key and private key generation

f = open("results.txt", "w")
f.write("Public key n:{0:s}  e:{1:s}\n".format(str(n), str(e)))
f.write("Private key n:{0:s}  d:{1:s}\n".format(str(n), str(d)))

symmetric_128_hex: str = (hex(random.getrandbits(128)))[2:]                                                             #128 bit key generation,encryption and decryption
symmetric_128 = np.fromstring(symmetric_128_hex, dtype=np.uint8)
f.write("128 bit original : {0:s}\n".format(str(symmetric_128_hex)))
encrypted_128, trash, d = encryptSymmetric(symmetric_128)                                                               #encryptSymmetric and decryptSymmetric functions are in RSA.py
f.write("128 bit encrypted : {0:s}\n".format(str(encrypted_128)))
decrypted_128 = decryptSymmetric(encrypted_128, d)
f.write("128 bit decrypted : {0:s}\n".format(str(decrypted_128)))
f.write("\n")

symmetric_256_hex: str = (hex(random.getrandbits(256)))[2:]                                                             #256 bit key generation,encryption and decryption
symmetric_256 = np.fromstring(symmetric_256_hex, dtype=np.uint8)
f.write("256 bit original : {0:s}\n".format(str(symmetric_256_hex)))
encrypted_256, trash, d = encryptSymmetric(symmetric_256)
f.write("256 bit encrypted : {0:s}\n".format(str(encrypted_256)))
decrypted_256 = decryptSymmetric(encrypted_256, d)
f.write("256 bit decrypted : {0:s}\n".format(str(decrypted_256)))
f.write("\n")

symmetric_1024_hex: str = (hex(random.getrandbits(1024)))[2:]                                                           #1024 bit key generation,encryption and decryption
symmetric_1024 = np.fromstring(symmetric_1024_hex, dtype=np.uint8)
f.write("1024 bit original : {0:s}\n".format(str(symmetric_1024_hex)))
encrypted_1024, trash, d = encryptSymmetric(symmetric_1024)
f.write("1024 bit encrypted : {0:s}\n".format(str(encrypted_1024)))
decrypted_1024 = decryptSymmetric(encrypted_1024, d)
f.write("1024 bit decrypted : {0:s}\n".format(str(decrypted_1024)))
f.write("\n")

sign, keyForHMAC, d = signature(data, symmetric_128_hex, symmetric_1024_hex, "-HMAC-SHA256-", back)                     #HMAC authentication
f.write("\tDigital signature: {0:s} \n".format(str(sign)))
decrypt(symmetric_128_hex, keyForHMAC, n, d, "-HMAC-SHA256-", back, sign)                                               #sign and decrypt functions are in HMAC.py
f.write("\n")

f.write("AES-CBC 128 bit encryption\n")
startEnc= timer()
f.write("\tEncryption started {0:s}\n".format(str(startEnc)))
enc = EncryptAES(data, symmetric_128_hex, AES.MODE_CBC, 128, back)                                                      #image AES encryptions and decryptions
finishEnc= timer()
f.write("\tEncryption finished {0:s}\n".format(str(finishEnc)))
startDec= timer()
f.write("\tDecryption started {0:s}\n".format(str(startDec)))
dec = DecryptAES(enc, symmetric_128_hex, AES.MODE_CBC, 128, back)                                                       #EncryptAES and DecryptAES functions are in aes.py
finishDec= timer()
f.write("\tDecryption finished {0:s}\n".format(str(finishDec)))
f.write("\tEncryption time: {0:s} Decryption time: {1:s} Elapsed time rate of encryption and decryption: {2:s}\n"
        .format(str((finishEnc-startEnc)), str((finishDec-startDec)), str((finishEnc-startEnc)/(finishDec-startDec))))
f.write("\n")

f.write("AES-CBC 256 bit encryption\n")
startEnc= timer()
f.write("\tEncryption started {0:s}\n".format(str(startEnc)))
enc = EncryptAES(data, symmetric_256_hex, AES.MODE_CBC, 256, back)
finishEnc= timer()
f.write("\tEncryption finished {0:s}\n".format(str(finishEnc)))
startDec= timer()
f.write("\tDecryption started {0:s}\n".format(str(startDec)))
dec = DecryptAES(enc, symmetric_256_hex, AES.MODE_CBC, 256, back)
finishDec= timer()
f.write("\tDecryption finished {0:s}\n".format(str(finishDec)))
f.write("\tEncryption time: {0:s} Decryption time: {1:s} Elapsed time rate of encryption and decryption: {2:s}\n"
        .format(str((finishEnc-startEnc)), str((finishDec-startDec)), str((finishEnc-startEnc)/(finishDec-startDec))))
f.write("\n")

f.write("AES-CTR 256 bit encryption\n")
startEnc= timer()
f.write("\tEncryption started {0:s}\n".format(str(startEnc)))
enc = EncryptAES(data, symmetric_256_hex, AES.MODE_CTR, 256, back)
finishEnc= timer()
f.write("\tEncryption finished {0:s}\n".format(str(finishEnc)))
startDec= timer()
f.write("\tDecryption started {0:s}\n".format(str(startDec)))
dec = DecryptAES(enc, symmetric_256_hex, AES.MODE_CTR, 256, back)
finishDec= timer()
f.write("\tDecryption finished {0:s}\n".format(str(finishDec)))
f.write("\tEncryption time: {0:s} Decryption time: {1:s} Elapsed time rate of encryption and decryption: {2:s}\n"
        .format(str((finishEnc-startEnc)), str((finishDec-startDec)), str((finishEnc-startEnc)/(finishDec-startDec))))