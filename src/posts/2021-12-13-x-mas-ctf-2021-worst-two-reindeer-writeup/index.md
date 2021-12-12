---
path: /posts/2021-12-13-x-mas-ctf-2021-worst-two-reindeer-writeup
title: X-MAS CTF 2021 - Worst two reindeer
date: 2021-12-13
tags: ctf,writeup,crypto
---

# Worst two reindeer

> This year, Santa decided to pair up two of his worst reindeer to pull his sleigh, hoping that two wrongs can make a right.
>
> He chose Randolf and Xixen to do this deed. They first had to come up with some cryptography challenge that should prove their superior intellect.
>
> They came up with some block cipher and asked you to proof check their work. Do your worst and show them who's the boss.
> 
> `nc challs.xmas.htsp.ro 1035`

`challenge.py`:

```py
from utils import *
from constants import *


def round_function(inp, key):
    i1 = inp[:HALF_WORD_SIZE]
    i0 = inp[HALF_WORD_SIZE:]
    k1 = key[:HALF_WORD_SIZE]
    k0 = key[HALF_WORD_SIZE:]

    x = 2 * k1[7] + k1[3]

    o1 = rotate_right(xor(i0, k0), x)
    o0 = xor(rotate_left(i1, 3), k1)

    return o1 + o0


class cipher:
    def __init__(self, key):
        assert len(key) == KEY_SIZE // 8
        self.key = bytes_2_bit_array(key)
        self.round_keys = self._get_key_schedule()

    def _get_key_schedule(self):
        key_copy = self.key
        keys = []

        for i in range(ROUNDS):
            k3 = key_copy[0: HALF_WORD_SIZE]
            k1 = key_copy[HALF_WORD_SIZE: 2 * HALF_WORD_SIZE]
            k2 = key_copy[2 * HALF_WORD_SIZE: 3 * HALF_WORD_SIZE]
            k0 = key_copy[-HALF_WORD_SIZE:]

            keys.append(k1 + k0)

            k0 = xor(rotate_left(k0, 7), k1)
            k2 = rotate_right(xor(k2, k3), 5)
            k3 = rotate_left(xor(k3, k1), 2)
            k1 = xor(rotate_right(k1, 6), k2)

            key_copy = k3 + k2 + k1 + k0

        return keys

    def encrypt(self, plaintext):
        pt = bytes_2_bit_array(plaintext)
        assert len(pt) == BLOCK_SIZE

        pt1 = pt[:WORD_SIZE]
        pt0 = pt[WORD_SIZE:]

        for i in range(ROUNDS):
            pt1, pt0 = pt0, xor(pt1, round_function(pt0, self.round_keys[i]))

        return bit_array_2_bytes(pt1 + pt0)

    def decrypt(self, ciphertext):
        ct = bytes_2_bit_array(ciphertext)
        assert len(ct) == BLOCK_SIZE

        ct0 = ct[:WORD_SIZE]
        ct1 = ct[WORD_SIZE:]

        for i in range(ROUNDS - 1, -1, -1):
            ct1, ct0 = ct0, xor(ct1, round_function(ct0, self.round_keys[i]))

        return bit_array_2_bytes(ct0 + ct1)
```

`constants.py`:

```py
POW_NIBBLES = 5
ACTION_CNT = 4

KEY_SIZE = 64
BLOCK_SIZE = 64
WORD_SIZE = 32
HALF_WORD_SIZE = 16
ROUNDS = 8
FLAG = '[REDACTED]'
```

`utils.py`:

```py
def bytes_2_bit_array(x):
    result = []
    for b in x:
        result += [int(a) for a in bin(b)[2:].zfill(8)]
    return result


def bit_array_2_bytes(x):
    result = b''
    for i in range(0, len(x), 8):
        result += int(''.join([chr(a + ord('0')) for a in x[i: i + 8]]), 2).to_bytes(1, byteorder='big')
    return result


def xor(a, b):
    return [x ^ y for x, y in zip(a, b)]


def rotate_right(arr, shift):
    return arr[-shift:] + arr[:-shift]


def rotate_left(arr, shift):
    return arr[shift:] + arr[:shift]
```

## Challenge Overview

After connecting and solving the pow, we are presented with a challenge:

```
Randolf: Hey, so... Santa gave us a challenge and we did our best but we need help from someone experienced with cryptography to check our work!
Xixen: We need to see if you can encrypt any plaintext if we only give you one plaintext-ciphertext pair
Randolf: If you do so, hopefully you won't though :), we will reward you with one present from Santa's personal Christmas tree
Xixen: Now get to work! You'll also have to prove that the exploit is consistent so you will have to do it 4 times. Good luck!

Step #1 of 4
plaintext = b'9ec55499ff13d2ee'
ciphertext = b'e6e761cdcb9504c0'

Please encrypt this plaintext for us:

plaintext = b'c642dc17d7b9d78c'

Give me an integer in hexadecimal format
ciphertext =
```

To get the flag, we need to solve 4 identical challenges each of which consists of encrypting an arbitrary plaintext, given just one plaintext-ciphertext pair for the challenge's custom block cipher.

It's reasonable to assume that the goal is key recovery. And given that we only have one plaintext-ciphertext pair, we thought that the cipher would be completely linear, in which case the key could be recovered by forming a system of linear equations involving the plaintext, key, and ciphertext, then solve for the key bits.

## The Block Cipher

The block cipher in the challenge operates on 8-byte blocks. It's a Feistel cipher with mostly constant shift rotate and XOR operations. The key schedule consists entirely of constant shift rotations and XORs, so we can safely assume that each round key can be expressed as a linear function of the cipher key. The round function is the part we need to study the most. It consists of a variable shift rotation which depends on some bits of the round key. This adds some nonlinearity to the cipher which will be annoying to deal with if our plan is to try and express the entire encryption process as a system of linear equations. Fortunately, it turns out to be not that big of an obstacle; since there are 8 rounds, and the possible values of the variable shift amount is between `0` and `3` (inclusive), then the total number of possibilities for the variable shift amounts is $4^8 = 2^{16}$. This is a fairly reasonable amount to bruteforce; the idea will be to exhaust over the possible shift amounts, then treat the system as if it were a completely linear system.

## Crafting the System of Equations

We've already been given the block cipher implementation, so we can take it easy and let Sage do most of the work. This is a useful technique to know; we can evaluate the encryption of a plaintext with some symbolic key variables, which in this case, are variables of a polynomial ring over $\mathbb{F}_2$. We'll write everything as vectors with entries in $\mathbb{F}_2$, so XOR will be replaced with addition.

Assume we know (since we're bruteforcing it) the variable shift amounts used in the round function. When we run through the encryption process with the symbolic key variables, if we inspect the result of the encryption, we'll notice that each entry in the resulting ciphertext vector is a linear combination of the key bits. With an equality between each entry of this result, and each ciphertext bit, we have a linear system of 64 equations in 64 variables! We can solve for the key unknowns by adding the ciphertext to the encryption result, taking the coefficient matrix of the linear equations, and then looking through the (right) kernel of this matrix.

But! Most of the time, the kernel will have some vectors in it which work as a valid key, _with_ the assumed shift amounts. To reduce the number of false positives, we filter through the elements of the kernel by only taking the keys that match the assumed shift amounts. That is, the keys that would yield the same variable shift amounts as what we assumed (if we were to run the key schedule and pick the relevant bits for each round key). In hindsight, it may have been more efficient to bruteforce the two relevant bits in each round key instead of going the other way and bruteforcing the shifts themselves. But, I think this way is easier to think about and implement.

## Efficiency and Reliability

The implementation isn't very efficient; it takes around 20 minutes to exhaust over the $2^{16}$ shift amounts and recover the key. From purely empirical observations, it seems like there are two keys valid keys (which satisfy the given plaintext-ciphertext pair, as well as matching the assume shift variables). Since we have no way of telling which is the actual key, we have a 1/2 probability of getting it right. The challenge originally required us to solve 4 in a row (but was later changed to 2). We managed to solve the original version by leaving it running overnight and hoping for the best.

## Implementation

```py
import os
os.environ['PWNLIB_NOTERM'] = 'True'
from pwn import *
from hashlib import sha256
import itertools
from tqdm import tqdm

WORD_SIZE = 32
ROUNDS = 8

def bytes_to_vec(x):
    result = []
    for b in x:
        result += [int(a) for a in bin(b)[2:].zfill(8)]
    return vector(P, result)

def bit_array_2_bytes(x):
    return int(''.join(map(str, x)), 2).to_bytes(8, byteorder='big')

def rotate_right(arr, shift):
    return vector(P, list(arr[-shift:]) + list(arr[:-shift]))

def rotate_left(arr, shift):
    return vector(P, list(arr[shift:]) + list(arr[:shift]))

def get_key_schedule(key):
    key_copy = key
    keys = []

    for i in range(ROUNDS):
        k3 = vector(P, key_copy[0: WORD_SIZE//2])
        k1 = vector(P, key_copy[WORD_SIZE//2: 2 * WORD_SIZE//2])
        k2 = vector(P, key_copy[2 * WORD_SIZE//2: 3 * WORD_SIZE//2])
        k0 = vector(P, key_copy[-WORD_SIZE//2:])

        keys.append(vector(P, list(k1) + list(k0)))

        k0 = rotate_left(k0, 7) + k1
        k2 = rotate_right(k2 + k3, 5)
        k3 = rotate_left(k3 + k1, 2)
        k1 = rotate_right(k1, 6) + k2

        key_copy = vector(P, list(k3) + list(k2) + list(k1) + list(k0))

    return keys

def round_function(inp, key, x):
    i1 = inp[:WORD_SIZE//2]
    i0 = inp[WORD_SIZE//2:]
    k1 = key[:WORD_SIZE//2]
    k0 = key[WORD_SIZE//2:]

    o1 = rotate_right(i0 + k0, x)
    o0 = rotate_left(i1, 3) + k1

    return vector(P, list(o1) + list(o0))

def encrypt(pt, round_keys, Xs):
    pt1 = pt[:WORD_SIZE]
    pt0 = pt[WORD_SIZE:]

    for i in range(ROUNDS):
        pt1, pt0 = pt0, pt1 + round_function(pt0, round_keys[i], Xs[i])

    return vector(P, list(pt1) + list(pt0))

def eqns_to_matrix(eqns):
    M = []
    for eq in eqns:
        r = [0]*65
        for c in eq:
            r[K_[c]] = 1
        M.append(r)
    return Matrix(GF(2), M)

def check_Xs(round_keys, Xs):
    for i in range(ROUNDS):
        key = round_keys[i]
        k1 = key[:WORD_SIZE//2]
        x = 2*int(k1[7]) + int(k1[3])
        if x != Xs[i]:
            return False
    return True

def recover_key(pt, ct):
    round_keys = get_key_schedule(K)
    for Xs in tqdm(list(itertools.product([0,1,2,3], repeat=8))):
        enc_pt = encrypt(pt, round_keys, Xs)
        M = eqns_to_matrix(list(enc_pt + ct))

        # check if the Xs match with the recovered key values
        for key in M.right_kernel():
            if key[-1] == GF(2)(0):
                continue
            key = key[:-1]
            rks = get_key_schedule(key)
            if check_Xs(rks, Xs):
                print('found key!', key, Xs)
                print(rks)
                print(M.right_nullity())
                return rks, Xs

P = BooleanPolynomialRing(64, [f'k_{i}' for i in range(64)])

K = list(P.gens())
K_ = { k: i for i,k in enumerate(K) }
K_[P(1)] = -1

def solve_pow(target):
    def f(x):
        hashresult = hashlib.sha256(x.encode()).hexdigest()
        return hashresult[-5:] == target
    ans = util.iters.mbruteforce(f, string.digits + string.ascii_letters, 4, 'upto')
    return ans.encode().hex()

def solve_step(conn):
    conn.recvuntil(b'plaintext =')
    pt = conn.recvline().decode().split(" b'")[1].strip("'\n")
    ct = conn.recvline().decode().split(" b'")[1].strip("'\n")
    conn.recvuntil(b'plaintext =')
    target = conn.recvline().decode().split(" b'")[1].strip("'\n")

    print(pt, ct, target)
    pt = bytes_to_vec(bytes.fromhex(pt))
    ct = bytes_to_vec(bytes.fromhex(ct))
    target = bytes_to_vec(bytes.fromhex(target))

    print('attempting to recover key...')
    rks, Xs = recover_key(pt, ct)
    c = encrypt(target, rks, Xs)
    c = bit_array_2_bytes(list(c))

    conn.sendlineafter('ciphertext = ', c.hex())

def attempt():
    conn = remote('challs.xmas.htsp.ro', 1035)
    target = conn.recvline().decode().strip()[-5:]
    ans = solve_pow(target)
    conn.sendline(ans)

    for _ in range(4):
        solve_step(conn)
        res = conn.recvline().decode()
        if 'Good' not in res:
            return False

    conn.interactive()
    return True

context.log_level = 'debug'
while True:
    if attempt():
        break
```

`X-MAS{RX_Cryp706r4phy_1s_N0t_S3cur3_W3_N33d_M0re_P0w3r!!!_9uh2f0uh}`
