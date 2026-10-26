import hmac
from Crypto.Cipher import AES

BLOCK = 16

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))

def mac(key: bytes, msg: bytes) -> bytes:
    if len(msg) == 0 or len(msg) % BLOCK != 0:
        raise ValueError("message must be a nonzero multiple of 16 bytes")
    cipher = AES.new(key, AES.MODE_ECB)
    x = bytes(BLOCK) # x_0 = 0^128
    for i in range(0, len(msg), BLOCK):
        x = cipher.encrypt(xor(msg[i:i + BLOCK], x)) # x_i = F_k(m_i ⊕ x_{i-1})
    return x # t = x_l

def verify(key: bytes, msg: bytes, tag: bytes) -> bool:
    if len(msg) == 0 or len(msg) % BLOCK != 0 or len(tag) != BLOCK:
        return False
    return hmac.compare_digest(mac(key, msg), tag)