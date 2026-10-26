from cbc_mac.implementation import mac, verify, xor
from pytest import raises

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

def test_known_answers():
    message  = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    expected = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")
    result   = mac(KEY, message)
    assert result == expected
    assert verify(KEY, message, expected)
    
    message += bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51")
    expected = bytes.fromhex("b148c17f309ee692287ae57cf12add49")
    result   = mac(KEY, message)
    assert result == expected
    assert verify(KEY, message, expected)

    message += bytes.fromhex("30c81c46a35ce411e5fbc1191a0a52ef")
    expected = bytes.fromhex("c93d11bfaf08c5dc4d90b37b4dee002b")
    result   = mac(KEY, message)
    assert result == expected
    assert verify(KEY, message, expected)

    message += bytes.fromhex("f69f2445df4f9b17ad2b417be66c3710")
    expected = bytes.fromhex("a7356e1207bb406639e5e5ceb9a9ed93")
    result   = mac(KEY, message)
    assert result == expected
    assert verify(KEY, message, expected)

def test_invalid_message_length():
    valid_tag = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")

    # empty message
    message = bytes.fromhex("")
    with raises(ValueError):
        mac(KEY, message)
    assert verify(KEY, message, valid_tag) == False

    # message length is 17 bytes
    message = bytes.fromhex("48656c6c6f576f726c64496e76616c6964")
    with raises(ValueError):
        mac(KEY, message)
    assert verify(KEY, message, valid_tag) == False

def test_invalid_tag_length():
    valid_message = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")

    # tag length is 0 bytes
    tag = bytes.fromhex("")
    assert verify(KEY, valid_message, tag) == False
    
    # tag length is 15 bytes
    tag = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef")
    assert verify(KEY, valid_message, tag) == False

    # tag length is 17 bytes
    tag = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef9700")
    assert verify(KEY, valid_message, tag) == False

def test_flipped_message_bit():
    message  = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    tag      = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")   
    # flip a bit in the message
    message  = xor(message, bytes.fromhex("01000000000000000000000000000000"))
    assert verify(KEY, message, tag) == False

    message += bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51")
    tag      = bytes.fromhex("b148c17f309ee692287ae57cf12add49")
    assert verify(KEY, message, tag) == False
    
    message += bytes.fromhex("30c81c46a35ce411e5fbc1191a0a52ef")
    tag      = bytes.fromhex("c93d11bfaf08c5dc4d90b37b4dee002b")
    assert verify(KEY, message, tag) == False
    
    message += bytes.fromhex("f69f2445df4f9b17ad2b417be66c3710")
    tag      = bytes.fromhex("a7356e1207bb406639e5e5ceb9a9ed93")
    assert verify(KEY, message, tag) == False

def test_flipped_tag_bit():
    message  = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    tag      = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")
    # flip a bit in the tag
    tag      = xor(tag, bytes.fromhex("00000000000000000000000000000100"))
    assert verify(KEY, message, tag) == False

    message += bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51")
    tag      = bytes.fromhex("b148c17f309ee692287ae57cf12add49")
    # flip a bit in the tag
    tag      = xor(tag, bytes.fromhex("00000000000000000000000000000100"))
    assert verify(KEY, message, tag) == False
    
    message += bytes.fromhex("30c81c46a35ce411e5fbc1191a0a52ef")
    tag      = bytes.fromhex("c93d11bfaf08c5dc4d90b37b4dee002b")
    # flip a bit in the tag
    tag      = xor(tag, bytes.fromhex("00000000000000000000000000000100"))
    assert verify(KEY, message, tag) == False
    
    message += bytes.fromhex("f69f2445df4f9b17ad2b417be66c3710")
    tag      = bytes.fromhex("a7356e1207bb406639e5e5ceb9a9ed93")
    # flip a bit in the tag
    tag      = xor(tag, bytes.fromhex("00000000000000000000000000000100"))
    assert verify(KEY, message, tag) == False