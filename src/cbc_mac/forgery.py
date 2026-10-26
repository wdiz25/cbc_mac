from Crypto.Random import get_random_bytes
from cbc_mac.implementation import mac, verify, xor, BLOCK

class Oracle:
    def __init__(self, fixed_blocks: int | None = None):
        self._key = get_random_bytes(BLOCK)
        self.queried: list[tuple[bytes, bytes | None]] = []
        self.fixed_blocks = fixed_blocks

    def query(self, msg: bytes) -> bytes:
        if self.fixed_blocks is not None and len(msg) != BLOCK * self.fixed_blocks:
            self.queried.append((msg, None))
            raise ValueError(f"oracle accepts only {self.fixed_blocks}-block messages")
        tag = mac(self._key, msg)
        self.queried.append((msg, tag))
        return tag

    def verify(self, msg: bytes, tag: bytes) -> bool:
        if self.fixed_blocks is not None and len(msg) != BLOCK * self.fixed_blocks:
            return False
        return verify(self._key, msg, tag)

    def was_queried(self, msg: bytes) -> bool:
        return any(m == msg for m, _ in self.queried)

def forge(query, target: bytes) -> bytes:
    t1 = query(target[:BLOCK]) # query M_1
    t2 = query(xor(target[BLOCK:BLOCK*2], t1) + target[BLOCK*2:]) # (M_2 ⊕ t_1) ‖ M_3 ‖ … M_L
    return t2
