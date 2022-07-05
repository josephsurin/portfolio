---
path: /posts/2022-07-05-google-ctf-2022-maybe-someday-writeup
title: Google CTF 2022 - Maybe Someday
date: 2022-07-05
tags: ctf,writeup,crypto
---


> Leave me your ciphertexts. I will talk to you later.
>
> `maybe-someday.2022.ctfcompetition.com 1337`


```py
#!/usr/bin/python3

# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from Crypto.Util.number import getPrime as get_prime
import math
import random
import os
import hashlib

# Suppose gcd(p, q) = 1. Find x such that
#   1. 0 <= x < p * q, and
#   2. x = a (mod p), and
#   3. x = b (mod q).
def crt(a, b, p, q):
    return (a*pow(q, -1, p)*q + b*pow(p, -1, q)*p) % (p*q)

def L(x, n):
    return (x-1) // n

class Paillier:
    def __init__(self):
        p = get_prime(1024)
        q = get_prime(1024)

        n = p * q
        λ = (p-1) * (q-1) // math.gcd(p-1, q-1) # lcm(p-1, q-1)
        g = random.randint(0, n-1)
        µ = pow(L(pow(g, λ, n**2), n), -1, n)

        self.n = n
        self.λ = λ
        self.g = g
        self.µ = µ

        self.p = p
        self.q = q

    # https://www.rfc-editor.org/rfc/rfc3447#section-7.2.1
    def pad(self, m):
        padding_size = 2048//8 - 3 - len(m)
        
        if padding_size < 8:
            raise Exception('message too long')

        random_padding = b'\0' * padding_size
        while b'\0' in random_padding:
            random_padding = os.urandom(padding_size)

        return b'\x00\x02' + random_padding + b'\x00' + m

    def unpad(self, m):
        if m[:2] != b'\x00\x02':
            raise Exception('decryption error')

        random_padding, m = m[2:].split(b'\x00', 1)

        if len(random_padding) < 8:
            raise Exception('decryption error')

        return m

    def public_key(self):
        return (self.n, self.g)

    def secret_key(self):
        return (self.λ, self.µ)

    def encrypt(self, m):
        g = self.g
        n = self.n

        m = self.pad(m)
        m = int.from_bytes(m, 'big')

        r = random.randint(0, n-1)
        c = pow(g, m, n**2) * pow(r, n, n**2) % n**2

        return c

    def decrypt(self, c):
        λ = self.λ
        µ = self.µ
        n = self.n

        m = L(pow(c, λ, n**2), n) * µ % n
        m = m.to_bytes(2048//8, 'big')

        return self.unpad(m)

    def fast_decrypt(self, c):
        λ = self.λ
        µ = self.µ
        n = self.n
        p = self.p
        q = self.q

        rp = pow(c, λ, p**2)
        rq = pow(c, λ, q**2)
        r = crt(rp, rq, p**2, q**2)
        m = L(r, n) * µ % n
        m = m.to_bytes(2048//8, 'big')

        return self.unpad(m)

def challenge(p):
    secret = os.urandom(2)
    secret = hashlib.sha512(secret).hexdigest().encode()

    c0 = p.encrypt(secret)
    print(f'{c0 = }')

    # # The secret has 16 bits of entropy.
    # # Hence 16 oracle calls should be sufficient, isn't it?
    # for _ in range(16):
    #     c = int(input())
    #     try:
    #         p.decrypt(c)
    #         print('😀')
    #     except:
    #         print('😡')

    # I decided to make it non-interactive to make this harder.
    # Good news: I'll give you 25% more oracle calls to compensate, anyways.
    cs = [int(input()) for _ in range(20)]
    for c in cs:
        try:
            p.fast_decrypt(c)
            print('😀')
        except:
            print('😡')

    guess = input().encode()

    if guess != secret: raise Exception('incorrect guess!')

def main():
    with open('/flag.txt', 'r') as f:
      flag = f.read()

    p = Paillier()
    n, g = p.public_key()
    print(f'{n = }')
    print(f'{g = }')

    try:
        # Once is happenstance. Twice is coincidence...
        # Sixteen times is a recovery of the pseudorandom number generator.
        for _ in range(16):
            challenge(p)
            print('💡')
        print(f'🏁 {flag}')
    except:
        print('👋')

if __name__ == '__main__':
    main()
```

# Challenge Overview

This challenge revolves around a guessing game that we need to win 16 times in a row. In each round, we need to guess a 2 byte secret. We are given the Paillier encryption of the secret's sha512 hexdigest and have access to 20 padding decryption oracle calls. The 20 oracle calls must be sent all at once, so we cannot adaptively choose each ciphertext. Before we see how to choose the ciphertexts to query the oracle with, let's review the encryption and padding scheme used.


## Paillier Cryptosystem

[Wikipedia](https://en.wikipedia.org/wiki/Paillier_cryptosystem) has a good overview of the cryptosystem used in the challenge. We summarise the important points here.

### Key Generation

The setup begins by generating two large primes $p$ and $q$ and computing $n = pq$. A random integer $g \in (\mathbb{Z}/n^2 \mathbb{Z})^\times$ is chosen and $(n, g)$ is the public key.

The private key is $(\lambda, \mu)$ where $\lambda = \mathrm{lcm}(p-1, q-1)$ and $\mu = (L(g^\lambda \mod n^2))^{-1} \pmod n$. Here, $L$ is the function $L(x) = \frac{x-1}{n}$ (integer division of $x-1$ by $n$).

### Encryption

Suppose we want to encrypt a message $m$. Paillier encryption is probabilistic, so a random $r \in (0, n)$ is chosen and the ciphertext is computed as $c = g^m r^n \pmod{n^2}$.

### Decryption

Given a ciphertext $c$ (and knowledge of the private key), we recover the plaintext by computing $m = L(c^\lambda \mod n^2) \cdot \mu \pmod n$.

### Homomorphic Property

The reason why the Paillier cryptosystem is interesting in this challenge is because it has a (nice?) property that is homomorphic addition; decrypting the _product_ of two ciphertext results in the _sum_ of their plaintexts. That is

$$
D(E(m_1) \cdot E(m_2) \mod {n^2}) = m_1 + m_2 \pmod n
$$

We can see why this holds by computing $E(m_1) \cdot E(m_2) \mod{n^2}$:

$$
\begin{aligned}
    E(m_1) \cdot E(m_2) &= (g^{m_1} r_1^n) \cdot (g^{m_2} r_2^n) \pmod{n^2} \\
                        &= g^{m_1 + m_2} (r_1 r_2)^n \pmod{n^2}
\end{aligned}
$$

and noting that the right hand side of this equation is the same as an encryption of $m_1 + m_2$ itself.

## PKCS#1 v1.5 Padding

The challenge uses [PKCS#1 v1.5](https://www.rfc-editor.org/rfc/rfc3447#section-7.2.1) padding to pad messages to 256 bytes before encryption. It works by putting the message $M$ in the following block format (as bytes):

<div style="border: 2px solid grey; width: 80%; margin-left: 10%; height: 50px; display: flex">
    <div style="border-right: 2px solid grey; height: 100%; width: 10%; text-align: center; line-height: 50px;">00</div>
    <div style="border-right: 2px solid grey; height: 100%; width: 10%; text-align: center; line-height: 50px;">02</div>
    <div style="border-right: 2px solid grey; height: 100%; width: 30%; text-align: center; line-height: 50px; white-space: nowrap">padding PS</div>
    <div style="border-right: 2px solid grey; height: 100%; width: 10%; text-align: center; line-height: 50px;">00</div>
    <div style="height: 100%; width: 40%; text-align: center; line-height: 50px; white-space: nowrap">message M</div>
</div><br/>

Here, the padding string $PS$ is a pseudorandom string of non-zero bytes and must be at least 8 bytes long. So, a properly padded plaintext should start with the bytes `\x00\x02` followed by the padding string and the message which are separated by a zero byte. Since the padding string doesn't contain any zero bytes, we can tell where the random padding ends and where the message starts by looking for the first zero byte that comes after the first two bytes.

Upon decryption, a decrypted plaintext not conforming to this block format will cause an error. Specifically, if the decrypted plaintext does not start with `\x00\x02`, or if the padding string is less than 8 bytes. It is the latter condition which we will target to gain information from the oracle results.

# Leaking Info From the Oracle

The main idea behind leaking information from the oracle is to use the homomorphic addition property on the given challenge ciphertext to cause the decryption to succeed or fail depending on the message. In the challenge, the message $M$ is the hexdigest of a sha512 hash. This means it will have length 128 bytes and contain only hexadecimal ASCII bytes. One easy way to cause the decryption to fail is to use homomorphic addition to add $2^{128 \times 8} = 2^{1024}$ to the challenge plaintext. The decrypted plaintext would look something like:

<div style="border: 2px solid grey; width: 80%; margin-left: 10%; height: 50px; display: flex">
    <div style="border-right: 2px solid grey; height: 100%; width: 10%; text-align: center; line-height: 50px;">00</div>
    <div style="border-right: 2px solid grey; height: 100%; width: 10%; text-align: center; line-height: 50px;">02</div>
    <div style="border-right: 2px solid grey; height: 100%; width: 30%; text-align: center; line-height: 50px; white-space: nowrap">padding PS</div>
    <div style="border-right: 2px solid grey; height: 100%; width: 10%; text-align: center; line-height: 50px;">01</div>
    <div style="height: 100%; width: 40%; text-align: center; line-height: 50px; white-space: nowrap">message M</div>
</div><br/>

and since none of the bytes in $PS$ or $M$ can be zero, the decryption will always fail.

Of course, doing this gives us exactly 0 bits of information about $M$, but it's a good start. We can now focus our attention on $M$ itself.

The possible values of the bytes of $M$ are `0x30-0x39` and `0x61-0x66` corresponding to `0-9` and `a-f` respectively. So if we use homomorphic addition to subtract a byte string consisting of 128 `0x30` bytes, then the resulting decrypted plaintext will contain a zero byte in the message if $M$ contains a `0x30` byte. If this is the case, then the decryption will succeed. As an example, the padded plaintext of a message hash hexdigest `23...0...6d` would become:

<div style="border: 2px solid grey; width: 80%; margin-left: 10%; height: 50px; display: flex">
    <div style="border-right: 2px solid grey; height: 100%; width: 10%; text-align: center; line-height: 50px;">00</div>
    <div style="border-right: 2px solid grey; height: 100%; width: 10%; text-align: center; line-height: 50px;">02</div>
    <div style="border-right: 2px solid grey; height: 100%; width: 20%; text-align: center; line-height: 50px;">PS</div>
    <div style="border-right: 2px solid grey; height: 100%; width: 10%; text-align: center; line-height: 50px;">01</div>
    <div style="height: 100%; width: 50%; text-align: center; line-height: 50px; white-space: nowrap">02 03 ... <b>00</b> ... 06 34</div>
</div><br/>

However, doing this gives us almost 0 bits of information about $M$ since it is all but guaranteed for at least one of the bytes in a hash hexdigest to be a `0x30` byte (only 16 out of the 65536 hash hexdigests don't contain a `0x30` byte).

So it makes sense to restrict the number of bytes that we consider.

# Choosing the Ciphertexts

Since we only get 20 queries, we need to be a bit smart about how we use them. Fortunately, it turns out we don't need to be _too_ smart, as a somewhat naive approach works quite well.

Suppose we only consider the last $n$ bytes of the message. We can use a probability argument to choose the best $n$. The probability that any of the last $n$ bytes is one particular byte out of the 16 possibilities is $1 - (15/16)^n$ (i.e. the complement of the probability that all $n$ bytes are _not_ one particular byte). The closer this value is to $0.5$, the more information we learn about what the message is and is not per query. $n = 11$ turns out to be the best choice.

At this point, our candidate ciphertexts are the encryptions of $2^{1024} - Z_b$ where $b$ ranges over the bytes `0x30-0x39` and `0x60-0x66`, and the $Z_b$ are the byte strings consisting of $11$ bytes of $b$.

We still have 4 more queries, so we can just do something similar except using a different block of $11$ bytes. Using the second last block of $11$ bytes with `0x30-0x33` byte strings is good enough.

# Recovering the Secret From the Results

When we craft a query, we can compute the subset of possible hashes which we know will correspond to a true result from the oracle. e.g. for the query corresponding to $2^{1024} - Z_f$, we know that every hash containing an `f` byte in the last $11$ bytes will return true from the oracle if it were the real secret.

Thus, each query result, both true and false, gives us some information about the message. If a query result is true, then we know the message lies within the subset of possible hashes corresponding to that query. If it is false, we know that the message is not in that subset (and is therefore in its complement). By taking the intersection of these subsets appropriately based on the oracle results, we should be left with just a few candidates.

# Expected Probability of Success

We can calculate how reliable a set of queries will be by enumerating all 65536 possible hashes and seeing the expected size of the each candidate set after looking through the queries.

```py
from hashlib import sha512
from tqdm import tqdm

H = [sha512(x.to_bytes(2, 'big')).hexdigest().encode() for x in range(0xffff + 1)]

Ks = []
for k in b'0123456789abcdef':
    z = bytes([0] * 117 + [k] * 11)
    K = []
    for i, h in enumerate(H):
        h_ = (int.from_bytes(h, 'big') - int.from_bytes(z, 'big')) % 2**1024
        if 0 in h_.to_bytes(128, 'big'):
            K.append(i)
    Ks.append(K)
for k in b'0123':
    z = bytes([0] * 106 + [k] * 11 + [0] * 11)
    K = []
    for i, h in enumerate(H):
        h_ = (int.from_bytes(h, 'big') - int.from_bytes(z, 'big')) % 2**1024
        if 0 in h_.to_bytes(128, 'big'):
            K.append(i)
    Ks.append(K)

R = []
for X in tqdm(range(0xffff+1)):
    T = set(range(0xffff+1))
    for K in Ks:
        if X in K:
            T &= set(K)
        else:
            T &= set(range(0xffff+1)) - set(K)
    R.append(T)

L = [len(r) for r in R]
expected_success = sum([L.count(i)/i for i in range(1, max(L))]) / len(L)
print(expected_success)
# 0.9173736572265625
```

On average, we expect to successfully solve one challenge with probability of around $0.917$. So we should be able to solve 16 consecutive challenges with probability of around $0.917^{16} \approx 0.25$. This means we should only need around 4 attempts to get the flag!

# Solve Script

```py
from pwn import *
from hashlib import sha512


H = [sha512(x.to_bytes(2, 'big')).hexdigest().encode() for x in range(0xffff + 1)]

Ks = []
for k in b'0123456789abcdef':
    z = bytes([0] * 117 + [k] * 11)
    K = []
    for i, h in enumerate(H):
        h_ = (int.from_bytes(h, 'big') - int.from_bytes(z, 'big')) % 2**1024
        if 0 in h_.to_bytes(128, 'big'):
            K.append(i)
    Ks.append(K)
for k in b'0123':
    z = bytes([0] * 106 + [k] * 11 + [0] * 11)
    K = []
    for i, h in enumerate(H):
        h_ = (int.from_bytes(h, 'big') - int.from_bytes(z, 'big')) % 2**1024
        if 0 in h_.to_bytes(128, 'big'):
            K.append(i)
    Ks.append(K)

def check_results(res):
    T = set(range(0xffff+1))
    for i, K in enumerate(Ks):
        if res[i]:
            T &= set(K)
        else:
            T &= set(range(0xffff+1)) - set(K)
    return list(T)[0]


def go():
    def paillier_homomorphic_add(c, m2):
        c2 = pow(g, m2, n**2)
        return c * c2 % n**2

    def create_query_ct_1(c, b):
        z = int.from_bytes(bytes([0] * 117 + [b] * 11), 'big')
        return paillier_homomorphic_add(c, -z)

    def create_query_ct_2(c, b):
        z = int.from_bytes(bytes([0] * 106 + [b] * 11 + [0] * 11), 'big')
        return paillier_homomorphic_add(c, -z)

    conn = remote('maybe-someday.2022.ctfcompetition.com', 1337)
    conn.recvline()

    n = int(conn.recvline().decode().split('n = ')[1])
    g = int(conn.recvline().decode().split('g = ')[1])

    for rnd in range(16):
        c0 = int(conn.recvline().decode().split('c0 = ')[1])
        c1 = paillier_homomorphic_add(c0, pow(2, 128 * 8))

        for b in b'0123456789abcdef':
            cb = create_query_ct_1(c1, b)
            conn.sendline(str(cb).encode())
        for b in b'0123':
            cb = create_query_ct_2(c1, b)
            conn.sendline(str(cb).encode())

        res = [conn.recvline().decode().strip() == '😀' for _ in range(20)]

        ans = check_results(res)
        conn.sendline(sha512(ans.to_bytes(2, 'big')).hexdigest().encode())
        r = conn.recvline().decode().strip()
        print(f'Round {rnd + 1} {r}')
        if r == '👋':
            conn.close()
            return

    conn.interactive()


while True:
    go()

# CTF{p4dd1n9_or4cl3_w1th_h0mom0rph1c_pr0p3r7y_c0m6in3d_in7o_a_w31rd_m47h_puzz1e}
```
