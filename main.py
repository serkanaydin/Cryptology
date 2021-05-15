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

symmetric_128_hex: str = (hex(random.getrandbits(128)))[2:]
print("128 bit original")
print(symmetric_128_hex)
symmetric_128 = np.fromstring(symmetric_128_hex, dtype=np.uint8)
encrypted_128,trash,d = encryptSymmetric(symmetric_128)
decrypted_128 = decryptSymmetric(symmetric_128,d)

symmetric_256_hex = (hex(random.getrandbits(256)))[2:]
print("256 bit original")
print(symmetric_256_hex)
symmetric_256 = np.fromstring(symmetric_256_hex, dtype=np.uint8)
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
sign,keyForHMAC,d = signature(data, symmetric_128_hex, symmetric_1024_hex, "-HMAC-SHA256-", back)
print(encrypted_128)
decrypt(data, symmetric_128_hex, keyForHMAC,n,d, "-HMAC-SHA256-", back, sign)

enc = EncryptAES(data, symmetric_128_hex, AES.MODE_CBC, 128, back)
dec = DecryptAES(enc, symmetric_128_hex, AES.MODE_CBC, 128, back)

enc = EncryptAES(data, symmetric_256_hex, AES.MODE_CBC, 256, back)
dec = DecryptAES(enc, symmetric_256_hex, AES.MODE_CBC, 256, back)

enc = EncryptAES(data, symmetric_256_hex, AES.MODE_CTR, 256, back)
dec = DecryptAES(enc, symmetric_256_hex, AES.MODE_CTR, 256, back)
