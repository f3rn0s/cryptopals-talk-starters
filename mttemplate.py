#!/usr/bin/env python3
from libs.mtcipher import MTcipher

seed = 0

encrypted = MTcipher(seed).encrypt(b'example')

decrypted = MTcipher(seed).decrypt(encrypted)

print(encrypted)
print(decrypted)
