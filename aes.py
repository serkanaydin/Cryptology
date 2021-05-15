import binascii
import os

import Crypto
from Crypto import Random
from Crypto.Cipher import AES
from PIL import Image
from Crypto.Util import Counter


def pad(data):
    return data + b"\x00" * (16 - len(data) % 16)


def convert_to_RGB(data):
    r, g, b = tuple(map(lambda d: [data[i] for i in range(0, len(data)) if i % 3 == d], [0, 1, 2]))
    pixels = tuple(zip(r, g, b))
    return pixels


def EncryptAES(data, key, mode, name, image):
    global iv
    iv = Random.new().read(int(16))
    if mode != AES.MODE_CTR:
        cipher = AES.new(bytearray(key), mode, iv)
        mode = "AES-CBC"

    else:
        nonce = Random.get_random_bytes(8)
        iv = Counter.new(64, nonce)
        cipher = AES.new(bytearray(key), mode, counter=iv)
        mode = "AES-CTR"
    encrypted = cipher.encrypt(pad(data))[:len(data)]
    encrypted_RGB = convert_to_RGB(encrypted)
    encryptedImage = Image.new(image.mode, image.size)
    encryptedImage.putdata(encrypted_RGB)
    encryptedImage.save("encrypted" + mode + str(name) + ".png", "PNG")
    return encrypted


def DecryptAES(ciphertext, key, mode, name, image):
    if mode != AES.MODE_CTR:
        decrypter = AES.new(bytearray(key), mode, iv)
        mode = "AES-CBC"
    else:
        decrypter = AES.new(bytearray(key), mode, counter=iv)
        mode = "AES-CTR"
    decrypted = decrypter.decrypt(ciphertext)[:len(ciphertext)]
    decrypted = convert_to_RGB(decrypted)
    decryptedImage = Image.new(image.mode, image.size)
    decryptedImage.putdata(decrypted)
    decryptedImage.save("decrypted" + mode + str(name) + ".png", "PNG")
