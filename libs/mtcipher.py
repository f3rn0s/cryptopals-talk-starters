import struct

class MTrand():
    def __init__(self):
        self.MT = [0 for i in range(624)]
        self.lower_mask = (1 << 31) - 1
        self.upper_mask = int(str(-~self.lower_mask)[-32:])

    def set_mt(self, MT):
        self.MT = MT
        self.index = 625

    def seed(self, seed):
        self.index = 625
        self.MT[0] = seed

        for i in range(1, 624):
            temp = 1812433253 * (self.MT[i-1] ^ (self.MT[i-1] >> (30))) + i
            self.MT[i] = temp & 0xffffffff

    def extract_number(self):
        if self.index >= 624:
            self.twist()

        (u, d) = (11, 0xFFFFFFFF)
        (s, b) = (7, 0x9D2C5680)
        (t, c) = (15, 0xEFC60000)
        l = 18

        y = self.MT[self.index]
        y = y ^ ((y >> u) & d)
        y = y ^ ((y << s) & b)
        y = y ^ ((y << t) & c)
        y = y ^ (y >> l)

        self.index += 1
        return y & 0xffffffff

    def twist(self):
        for i in range(0, 624):
            x = (self.MT[i] & self.upper_mask) + (self.MT[(i+1) % 624] & self.lower_mask)

            xA = x >> 1

            if not x % 2 == 0:
                a = 0x9908B0DF
                xA = xA ^ a

            self.MT[i] = self.MT[(i + 397) % 624] ^ xA

        self.index = 0

def xor(buf1, buf2):
    return b''.join([bytes([buf1[i] ^ buf2[i % len(buf2)]]) for i in range(0, len(buf1))])

class MTcipher:
    def __init__(self, key):
        self._rng = MTrand()
        self._rng.seed(key)

    def encrypt(self, plaintext):
        keystream = b''

        # We use all the bits of the PRNG outputs (there is no need take just 16 bits per output)
        while len(keystream) < len(plaintext):
            keystream += struct.pack('>L', self._rng.extract_number())

        return xor(plaintext, keystream)

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)
