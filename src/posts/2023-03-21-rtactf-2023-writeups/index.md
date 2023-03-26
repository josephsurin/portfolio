---
path: /posts/2023-03-21-rtactf-2023-writeups
title: RTACTF 2023 - Crypto
date: 2023-03-21
tags: ctf,infosec,writeup,crypto
---

[RTACTF](https://rtactf.ctfer.jp) is a crypto/pwn speedrun CTF organised for fun by some Japanese CTFers. The challenges are really nice and relaxing to play through! I managed to solve all the crypto challenges within the target time :) Here are my solves for the problems.

# XOR-CBC

> 目標：480 sec
> 
> AES-CBC is secure right? Wait, do we really need the AES-part?
> 
> AES-CBCって安全ですよね。これもうAESの部分は要らないのでは？

```py
import os
import struct

FLAG = os.getenv("FLAG", "RTACTF{*** REDACTED ***}").encode()
assert FLAG.startswith(b"RTACTF{") and FLAG.endswith(b"}")

KEY_SIZE = 8
KEY = os.urandom(KEY_SIZE)

p64 = lambda x: struct.pack('<Q', x)
u64 = lambda x: struct.unpack('<Q', x)[0]

"""
XOR-CBC Explained:

     plain 0       plain 1       plain 2
        |             |             |
        v             v             v
IV --> XOR  +------> XOR  +------> XOR
        |   |         |   |         |
        v   |         v   |         v
key -> XOR  | key -> XOR  | key -> XOR
        |   |         |   |         |
        +---+         +---+         |
        |             |             |
        v             v             v
[IV] [cipher 0]    [cipher 1]    [cipher 2]
"""
def encrypt(plaintext, key):
    padlen = KEY_SIZE - (len(plaintext) % KEY_SIZE)
    plaintext += bytes([padlen] * padlen)

    iv = os.urandom(KEY_SIZE)
    ciphertext = iv
    for i in range(0, len(plaintext), KEY_SIZE):
        p_block = plaintext[i:i+KEY_SIZE]
        c_block = p64(u64(iv) ^ u64(p_block) ^ u64(key))
        ciphertext += c_block
        iv = c_block

    return ciphertext

def decrypt(ciphertext, key):
    iv, ciphertext = ciphertext[:KEY_SIZE], ciphertext[KEY_SIZE:]

    plaintext = b''
    for i in range(0, len(ciphertext), KEY_SIZE):
        c_block = ciphertext[i:i+KEY_SIZE]
        p_block = p64(u64(iv) ^ u64(c_block) ^ u64(key))
        plaintext += p_block
        iv = c_block

    return plaintext.rstrip(plaintext[-1:])

if __name__ == '__main__':
    ENC_FLAG = encrypt(FLAG, KEY)
    print("Encrypted:", ENC_FLAG.hex())
    assert decrypt(ENC_FLAG, KEY) == FLAG
```

```
Encrypted: 6528337d61658047295cef0310f933eb681e424b524bcc294261bd471ca25bcd6f3217494b1ca7290c158d7369c168b3
```

## Solution

The diagram in the handout helps a lot to understand the simple block cipher mode of operation. We are also hinted to use known plaintext from the flag format through the assertion line. We can recover the first 7 bytes of the key by xoring the first block of ciphertext with the IV and the known plaintext. Then we can xor the key and the previous ciphertext block with a ciphertext block to recover that plaintext block. For the last key byte, I just guessed and checked what made sense.

```py
from pwn import xor, u64, p64
from Crypto.Util.Padding import unpad

enc = bytes.fromhex('6528337d61658047295cef0310f933eb681e424b524bcc294261bd471ca25bcd6f3217494b1ca7290c158d7369c168b3')
iv = enc[:8]
blocks = [enc[8:][i:i+8] for i in range(0, len(enc)-8, 8)]
key = xor(iv, blocks[0], 'RTACTF{1'.encode()) # guess and check last byte
next_iv = blocks[0]
flag = 'RTACTF{1'.encode()
for block in blocks[1:]:
    dec = xor(block, next_iv, key)
    flag += dec
    # print(dec)
    next_iv = block
# print(flag)
print(unpad(flag, 8).decode())
# RTACTF{1_b0ugh7_4_b1k3_y3s73rd4y}
```

# Collision-DES

> 目標：720 sec
> 
> Is it possible to encrypt the same plaintext with completely different keys and get the same ciphertext?
> 
> 同じ平文をまったく異なる鍵で暗号化した結果が同じになることってあるんでしょうか。
> 
> `nc 35.194.118.87 7002`

```py
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
import os

FLAG = os.getenv("FLAG", "RTACTF{**** REDACTED ****}")

def encrypt(key, plaintext):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, 8))

if __name__ == '__main__':
    key1 = os.urandom(8)
    print(f"Key 1: {key1.hex()}")
    key2 = bytes.fromhex(input("Key 2: "))

    assert len(key1) == len(key2) == 8, "Invalid key size :("
    assert len(set(key1).intersection(set(key2))) == 0, "Keys look similar :("

    plaintext = b"The quick brown fox jumps over the lazy dog."
    if encrypt(key1, plaintext) == encrypt(key2, plaintext):
        print("[+] You found a collision!")
        print(FLAG)
    else:
        print("[-] Nope.")
```

## Solution

In this challenge, we are given a DES key and need to provide a different DES key which encrypts the same plaintext to the same ciphertext as the given key. Solving this challenge pretty much requires knowing that some bits (the 8th bit of each byte) of the DES key are parity bits and don't actually affect the encryption result, so we can just flip those bits which will give a different key but still encrypt the message to the same ciphertext.

```py
from pwn import *

conn = remote('35.194.118.87', 7002)
key1 = bytes.fromhex(conn.recvline().decode().split('1: ')[1])
ans = bytes([k ^ 1 for k in key1])
conn.sendlineafter(b'Key 2: ', ans.hex().encode())
print(conn.recvline().decode())
print(conn.recvline().decode())
# RTACTF{The_keysize_of_DES_is_actually_56-bit}
```

# Reused-AES

> 目標：1080 sec
> 
> I re-use the key and IV to reduce waste.
> 
> もったいないので鍵とIVは再利用しています。
> 
> `nc 35.194.118.87 7001`

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

iv = os.urandom(16)
key = os.urandom(16)
FLAG = os.getenv("FLAG", "RTACTF{**** REDACTED ****}").encode()

def encrypt(data):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.encrypt(pad(data, 16))

if __name__ == '__main__':
    print(encrypt(FLAG).hex())
    print(encrypt(input("> ").encode()).hex())
```

## Solution

This challenge is about [CFB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB)). The wikipedia page confused me a bit as I was looking at the diagram for full-block CFB, but pycryptodome is CFB-8 by default (i.e. the segment size is 8 bits). What that means is the key stream is only used to encrypt a single byte at a time. The flag is the same across connections, so we can make one connection per flag character to recover it given that we know the previous characters in the flag.

```py
from pwn import *
from string import printable

"""
C0 = E(IV) ^ M0
C0' = E(IV) ^ M0'

so

C0' ^ C0 = M0 ^ M0'
=> M0 = C0' ^ C0 ^ M0'

CFB-8, so one byte is encrypted at a time
to get the next 16byte block of keystream, 
the ciphertext for that one byte is appended to the previous 15 bytes of the ct (or iv)
"""

flag = 'RTACTF'.encode()
while True:
    conn = remote('35.194.118.87', 7001)
    ct = bytes.fromhex(conn.recvline().decode())
    conn.sendlineafter(b'> ', flag + b'X' * (len(ct) - len(flag)))
    ct0 = bytes.fromhex(conn.recvline().decode())
    conn.close()

    print(ct.hex())
    print(ct0.hex())

    next_m = ct[len(flag)] ^ ct0[len(flag)] ^ ord('X')
    print('next flag char:', next_m)
    flag += bytes([next_m])
    print('flag:', flag)

# RTACTF{name_it_AES-SDGs}
```

# 1R-AES

> 目標：1320 sec
> 
> Why does AES repeat the same operation 10 times? Why not once?
> 
> AESってなんで中で同じ処理10回も繰り返すんですか？1回で良くないすか？
> 
> `nc 35.194.118.87 7003`

```py
import aes
import os

key = os.getenv("KEY", "*** REDACTED ***").encode()
assert len(key) == 16

flag = os.getenv("FLAG", "RTACTF{*** REDACTED ***}")
assert flag.startswith("RTACTF{") and flag.endswith("}")
la = flag[len("RTACTF{"):-len("}")]
assert len(la) == 16

cipher = aes.AES(key)
print("enc(la):", cipher.encrypt_block(la.encode()).hex())

while True:
    cipher = aes.AES(key)
    plaintext = bytes.fromhex(input("msg > "))
    assert len(plaintext) == 16
    print("enc(msg):", cipher.encrypt_block(plaintext).hex())
```

`aes.py` is the implementation of AES [here](https://raw.githubusercontent.com/boppreh/aes/master/aes.py), except modified so that only one round is used:

```diff
181c181
<     rounds_by_key_size = {16: 10, 24: 12, 32: 14}
---
>     rounds_by_key_size = {16: 1, 24: 1, 32: 1}
```

## Solution

This is just one round AES. Modelling it in Z3 is enough to recover the two round keys with just three known plaintext/ciphertext pairs.

```py
from os import urandom
from pwn import *
from z3 import *
from tqdm import tqdm

from aes import s_box, shift_rows, add_round_key, inv_shift_rows, inv_sub_bytes

def bytes2matrix(text):
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    return sum(matrix, [])

def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = z3_SBOX(s[i][j])

def z3_encrypt(block, key0, key1):
    add_round_key(block, key0)
    sub_bytes(block)
    shift_rows(block)
    add_round_key(block, key1)

def decrypt(block, key0, key1):
    add_round_key(block, key1)
    inv_shift_rows(block)
    inv_sub_bytes(block)
    add_round_key(block, key0)

conn = remote('35.194.118.87', 7003)
la = bytes.fromhex(conn.recvline().decode().split(': ')[1])

solver = Solver()
z3_SBOX = Function('z3_SBOX', BitVecSort(8), BitVecSort(8))
for i in range(len(s_box)):
    solver.add(z3_SBOX(i) == s_box[i])

ptct_pairs = []
msgs = [urandom(16) for _ in range(3)]
for msg in msgs:
    conn.sendlineafter(b'> ', msg.hex().encode())
    ct = bytes.fromhex(conn.recvline().decode().split(': ')[1])
    ptct_pairs.append((msg, ct))

KEY0 = [BitVec(f'rk0_{i}', 8) for i in range(16)]
KEY1 = [BitVec(f'rk1_{i}', 8) for i in range(16)]

print('collecting ptct pairs...')
for pt, ct in tqdm(ptct_pairs):
    pt_mat = bytes2matrix(pt)
    z3_encrypt(pt_mat, bytes2matrix(KEY0), bytes2matrix(KEY1))
    z3_ct = pt_mat
    for a, b in zip(matrix2bytes(z3_ct), ct):
        solver.add(a == b)

print('solving...')
print(solver.check())
m = solver.model()

key0 = bytes([m[k].as_long() for k in KEY0])
key1 = bytes([m[k].as_long() for k in KEY1])

la = bytes2matrix(la)
decrypt(la, bytes2matrix(key0), bytes2matrix(key1))
la = matrix2bytes(la)

print('RTACTF{' + bytes(la).decode() + '}')
# RTACTF{MixColumnIsMust!}
```
