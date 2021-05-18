import binascii
import os

import Crypto
from Crypto import Random
from Crypto.Cipher import AES
from PIL import Image
from Crypto.Util import Counter


def pad(data):                                                                                                          #hexadecimal formatting
    return data + b"\x00" * (16 - len(data) % 16)


def convert_to_RGB(data):                                                                                               #converts data to RGB format to save as a image file or
    r, g, b = tuple(map(lambda d: [data[i] for i in range(0, len(data)) if i % 3 == d], [0, 1, 2]))                     #get a hex list to make encryption or decrpytion operations
    pixels = tuple(zip(r, g, b))
    return pixels


def EncryptAES(data, key, mode, name, image):
    global iv
    key = ''.join(
        map(str, str(key).replace("0x", "").replace("[", "").replace("'", "").replace(",", "").replace(" ", "").replace(
            "]", "")))                                                                                                  #hexadecimal formatting
    iv = Random.new().read(int(16))                                                                                     #128 bit IV generation
    if mode != AES.MODE_CTR:                                                                                            #cipher object instantiation for encryption in AES CBC MODE
        cipher = AES.new(bytearray.fromhex(key), mode, iv)
        mode = "AES-CBC"

    else:
        nonce = Random.get_random_bytes(8)                                                                              #cipher object instantiation for encryption in AES CTR MODE
        iv = Counter.new(64, nonce)
        cipher = AES.new(bytearray.fromhex(key), mode, counter=iv)
        mode = "AES-CTR"
    encrypted = cipher.encrypt(pad(data))[:len(data)]                                                                   #image encryption
    encrypted_RGB = convert_to_RGB(encrypted)                                                                           #encrypted image is converted to RGB format
    encryptedImage = Image.new(image.mode, image.size)
    encryptedImage.putdata(encrypted_RGB)
    encryptedImage.save("encrypted" + mode + str(name) + ".png", "PNG")                                                 #image is saved
    return encrypted                                                                                                    #encrypted image is returned to decrypt


def DecryptAES(ciphertext, key, mode, name, image):
    key = ''.join(map(str, str(key).replace("0x", "").replace("[", "").replace("'", "")
                      .replace(",", "").replace(" ", "").replace("]", "")))
    if mode != AES.MODE_CTR:                                                                                            #cipher instantiation for decryption with private key
        decrypter = AES.new(bytearray.fromhex(key), mode, iv)
        mode = "AES-CBC"
    else:
        decrypter = AES.new(bytearray.fromhex(key), mode, counter=iv)
        mode = "AES-CTR"
    decrypted = decrypter.decrypt(ciphertext)[:len(ciphertext)]
    decrypted = convert_to_RGB(decrypted)
    decryptedImage = Image.new(image.mode, image.size)
    decryptedImage.putdata(decrypted)
    decryptedImage.save("decrypted" + mode + str(name) + ".png", "PNG")
