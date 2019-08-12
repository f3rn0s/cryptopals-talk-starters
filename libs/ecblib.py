from Crypto.Cipher import AES
from string import printable as valid_chars
import struct
import random
import base64

def char(x):
    return chr(x).encode()

def keygen(length=16):
    return b''.join([bytes([i]) for i in random.choices(valid_chars.encode(), k=length)])

def AES_ECB_encrypt(ciphertext, key):
    return AES.new(key, AES.MODE_ECB).encrypt(ciphertext)

def pkcs(text, blocksize=16):
    size_diff = blocksize - (len(text) % blocksize)
    return text + (char(size_diff) * size_diff)

class Oracle():
    def __init__(self, secret):
        self.secret = secret
        self.key = keygen()

    def encrypt(self, plaintext):
        message = pkcs(plaintext + self.secret)
        return AES_ECB_encrypt(message, self.key)

_secret = base64.b64decode("""
d2VsY29tZSB0byB0aGUgc3VwZXIgc2VjcmV0IHN1cGVyIHNlY3VyZSBwYXJ0
IG9mIHRoaXMgbWVzc2FnZSwgdGhhdCBpZGVudGlmaWVzIHlvdSBhcyBhZG1p
biBvciBub3QhCm1hbiBJIGhvcGUgbm8gb25lIGV2ZXIgZ2V0cyBiYWNrIGhl
cmUgYW5kIHN0ZWFscyBteSBjb29raWVzID46Yw==
""")

oracle = Oracle(_secret)
