from cbc_mac.forgery import Oracle, forge
from cbc_mac.implementation import BLOCK

TARGET = b"from=alice&to=mallory&amount=1000000&note=rent!!"
TRIALS = 100

def demo() -> None:
    oracle = Oracle()
    forged = forge(oracle.query, TARGET)

    for (msg, tag) in oracle.queried:
        print(f"Query: {msg.hex()}")
        print(f"Tag:   {tag.hex()}")
    print(f"Forged Tag:     {forged.hex()}")
    print(f"Target Queried: {oracle.was_queried(TARGET)}")
    print(f"Verify:         {oracle.verify(TARGET, forged)}")

def trials() -> None:
    successes = 0
    for _ in range(TRIALS):
        oracle = Oracle()
        forged = forge(oracle.query, TARGET)
        if not oracle.was_queried(TARGET) and oracle.verify(TARGET, forged):
            successes += 1
    print(f"Successful Forgeries: {successes}/{TRIALS}")

def fixed_length() -> None:
    oracle = Oracle(fixed_blocks=3)
    try:
        forge(oracle.query, TARGET)
    except ValueError as e:
        msg, _ = oracle.queried[-1]
        print(f"Attack failed at query {len(oracle.queried)}: {msg.hex()} ({len(msg) // BLOCK} block)")
        print(f"Oracle error: {e}")

def main() -> None:
    print("--- 3b: Forgery Demo ---")
    demo()
    print("\n--- 3b: 100 Trials ---")
    trials()
    print("\n--- 3c: Fixed-Length (3 blocks) ---")
    fixed_length()