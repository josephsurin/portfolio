---
path: /post/2020-03-13-utctf-2020-writeups
title: UTCTF 2020 Writeups
date: 2020-03-13
tags: ctf,infosec,crypto
---

# Random ECB

## Crypto

```python
#!/usr/bin/env python

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits
from secret import flag

KEY = get_random_bytes(16)


def aes_ecb_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def encryption_oracle(plaintext):
    b = getrandbits(1)
    plaintext = pad((b'A' * b) + plaintext + flag, 16)
    return aes_ecb_encrypt(plaintext, KEY).hex()


if __name__ == '__main__':
    while True:
        print("Input a string to encrypt (input 'q' to quit):")
        user_input = input()
        if user_input == 'q':
            break
        output = encryption_oracle(user_input.encode())
        print("Here is your encrypted string, have a nice day :)")
        print(output)
```

## Solution

The service is an ECB encryption oracle that randomly prefixes the plaintext with an `'A'` with a probability of ~1/2. To exploit it, we use a slightly modified version of the [ECB byte at a time attack](https://github.com/ashutosh1206/Crypton/tree/master/Block-Cipher/Attack-ECB-Byte-at-a-Time). 

We see that for any input `I` we provide to the oracle, we will get the encryption of either `I+flag` or `'A'+I+flag`. So in order to get a crib for each byte, we first begin by seeing what the encryption of a full block of `'A'`s looks like. Then, we query with input `(15+15)*'A'` until the second block of output is different to the full block of `'A'`s. This block is the encryption of `15*'A'+flag[0]`. We can use this to bruteforce the first character of the flag. We continue in a similar manner, keeping a list of our seen cribs and sending `(16+15-len(flag))*'A'` each time until we get some encryption whose second block differs from anything in the list of seen cribs. Eventually, we will recover the full flag!

```python
from pwn import remote
from string import printable

conn = remote('crypto.utctf.live', 9005)

def blockify(d):
    return [d[i:i+32] for i in range(0, len(d), 32)]

def oracle_enc(p):
    conn.recvline()
    conn.sendline(p)
    conn.recvline()
    return blockify(conn.recvline())

flag = b'utflag{'

seen_cribs = [oracle_enc(b'A'*16)[0]]

searching_for_crib = True
j = 0

while flag.decode()[-1] != '}':
    if searching_for_crib:
        b = oracle_enc(b'A'*(16+15-len(flag)))
        if b[1] not in seen_cribs:
            seen_cribs.append(b[1])
            searching_for_crib = False
    else:
        crib = seen_cribs[-1]
        seen_blocks = []
        kouho = flag + printable[j%len(printable)].encode()
        while len(seen_blocks) < 2:
            b = oracle_enc(b'A'*(16+15-len(kouho))+kouho)
            if b[1] == crib:
                flag = kouho
                print(flag.decode())
                j = -1
                searching_for_crib = True
                break
            elif b[1] not in seen_blocks:
                seen_blocks.append(b[1])
        j += 1
```

Output:

```
utflag{3
utflag{3c
utflag{3cb
utflag{3cb_
utflag{3cb_w
utflag{3cb_w1
utflag{3cb_w17
utflag{3cb_w17h
utflag{3cb_w17h_
utflag{3cb_w17h_r
utflag{3cb_w17h_r4
utflag{3cb_w17h_r4n
utflag{3cb_w17h_r4nd
utflag{3cb_w17h_r4nd0
utflag{3cb_w17h_r4nd0m
utflag{3cb_w17h_r4nd0m_
utflag{3cb_w17h_r4nd0m_3
utflag{3cb_w17h_r4nd0m_3c
utflag{3cb_w17h_r4nd0m_3cb
utflag{3cb_w17h_r4nd0m_3cb}
```
