import sys
sys.path.append(".")
import numpy as np
from RSA import *
from aes import *
from HMAC import *

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
rsa_key_generation()

symmetric_128: str = (hex(random.getrandbits(64)))[2:]
print("128 bit original")
print(symmetric_128)
symmetric_128 = np.fromstring(symmetric_128, dtype=np.uint8)
encrypted_128,trash,d = encryptSymmetric(symmetric_128)
decrypted_128 = decryptSymmetric(symmetric_128,d)

symmetric_256 = (hex(random.getrandbits(128)))[2:]
print("256 bit original")
print(symmetric_256)
symmetric_256 = np.fromstring(symmetric_256, dtype=np.uint8)
encrypted_256,trash,d = encryptSymmetric(symmetric_256)
decrypted_256 = decryptSymmetric(encrypted_256,d)

symmetric_1024_hex: str = (hex(random.getrandbits(1024)))[2:]
print("1024 bit original")
print(symmetric_1024_hex)
symmetric_1024 = np.fromstring(symmetric_1024_hex, dtype=np.uint8)
encrypted_1024,trash,d = encryptSymmetric(symmetric_1024)
decrypted_1024 = decryptSymmetric(encrypted_1024,d)
print("hebele hübele")
print(symmetric_1024)
sign,keyForHMAC,d = signature(data, encrypted_128, symmetric_1024_hex, "-HMAC-SHA256-", back)
decrypt(data, encrypted_128, keyForHMAC,n,d, "-HMAC-SHA256-", back, sign)

enc = EncryptAES(data, encrypted_128, AES.MODE_CBC, 128, back)
dec = DecryptAES(enc, encrypted_128, AES.MODE_CBC, 128, back)

enc = EncryptAES(data, encrypted_256, AES.MODE_CBC, 256, back)
dec = DecryptAES(enc, encrypted_256, AES.MODE_CBC, 256, back)

enc = EncryptAES(data, encrypted_256, AES.MODE_CTR, 256, back)
dec = DecryptAES(enc, encrypted_256, AES.MODE_CTR, 256, back)
