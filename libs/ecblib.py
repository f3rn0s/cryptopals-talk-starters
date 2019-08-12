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

secret = base64.b64decode("""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
""")

oracle = Oracle(secret)
