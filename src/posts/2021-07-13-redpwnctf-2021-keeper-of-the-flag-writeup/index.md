---
path: /posts/2021-07-13-redpwnctf-2021-keeper-of-the-flag-writeup
title: redpwnCTF 2021 - Keeper of the Flag
date: 2021-07-13
tags: ctf,infosec,writeup,crypto
---

This year's redpwnCTF had some nice crypto challenges (scrambled-elgs, keeper-of-the-flag, retrosign), but also had some rather guessy and _bad_ challenges (round-the-bases, quaternion-revenge). Particularly quaternion-revenge, where we spent hours trying to work out a solution only to find that sending `i*i` (or something similar) gives the flag, despite this not even making sense (since `i*i = -p`). In hindsight, we should have tried this earlier, but regardless, having "strange" behaviour on the remote without there being a good reason for, or without it being made explicit, is poor challenge design. The crypto category was very easy compared to the other categories, but overall, the CTF was well-run and fun to play.

# Keeper of the Flag

> can you convince keeper of the flag to give you flag?
> 
> `nc mc.ax 31538`

```py
#!/usr/local/bin/python3

from Crypto.Util.number import *
from Crypto.PublicKey import DSA
from random import *
from hashlib import sha1

rot = randint(2, 2 ** 160 - 1)
chop = getPrime(159)

def H(s):
    x = bytes_to_long(sha1(s).digest())
    return pow(x, rot, chop)


L, N = 1024, 160
dsakey = DSA.generate(1024)
p = dsakey.p
q = dsakey.q
h = randint(2, p - 2)
g = pow(h, (p - 1) // q, p)
if g == 1:
    print("oops")
    exit(1)

print(p)
print(q)
print(g)

x = randint(1, q - 1)
y = pow(g, x, p)

print(y)


def verify(r, s, m):
    if not (0 < r and r < q and 0 < s and s < q):
        return False
    w = pow(s, q - 2, q)
    u1 = (H(m) * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r


pad = randint(1, 2 ** 160)
signed = []
for i in range(2):
    print("what would you like me to sign? in hex, please")
    m = bytes.fromhex(input())
    if m == b'give flag' or m == b'give me all your money':
        print("haha nice try...")
        exit()
    if m in signed:
        print("i already signed that!")
        exit()
    signed.append(m)
    k = (H(m) + pad + i) % q
    if k < 1:
        exit()
    r = pow(g, k, p) % q
    if r == 0:
        exit()
    s = (pow(k, q - 2, q) * (H(m) + x * r)) % q
    if s == 0:
        exit()
    print(H(m))
    print(r)
    print(s)

print("ok im done for now")
print("you visit the flag keeper...")
print("for flag, you must bring me signed message:")
print("'give flag':" + str(H(b"give flag")))

r1 = int(input())
s1 = int(input())
if verify(r1, s1, b"give flag"):
    print(open("flag.txt").readline())
else:
    print("sorry")
```

## Solution

The server implements DSA and requires us to forge a signature for the message "give flag" to get the flag. We can obtain two signatures from the server for two different messages (other than the message that we need to sign to get the flag).

### DSA Overview

Below is a brief overview of DSA, see [wikipedia](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm) for full details.

#### Parameter/Key Generation

1. Choose a key length $L$ and a modulus length $N$ (common values, and the values used in the challenge, are $(1024, 160)$)
2. Choose an $N$-bit prime $q$, and an $L$-bit prime $p$ such that $q \mid p-1$
3. Choose a random $h \in \{ 2, \ldots, p-2 \}$ and compute $g \equiv h^{(p-1)/q} \pmod p$. This is done so that $g$ is a generator of the subgroup of $(\mathbb{Z}/p\mathbb{Z})^\times$ order $q$
4. Choose a secret signing key $x \in \{ 1, \ldots, q-1 \}$
5. Compute $y \equiv g^x \pmod p$
6. The private key is $x$ and the public key is $y$

#### Signing

To sign a message $m$:

1. Choose a random nonce $k \in \{ 1, \ldots, q-1 \}$ (this must be random!)
2. Compute $r \equiv (g^k \mod p) \pmod q$
3. Compute $s \equiv k^{-1} (H(m) + xr) \pmod q$, where $H$ is a cryptographic hash function

The signature is $(r, s)$.

#### Verification

To verify a signature $(r, s)$:

1. Check that $0 < r < q$ and $0 < s < q$, otherwise return invalid signature
2. Compute $w = s^{-1} \pmod q$
3. Compute $u_1 = H(m) w \pmod q$
4. Compute $u_2 = rw \pmod q$
5. Check that $r \equiv (g^{u_1} y^{u_2} \mod p) \pmod q$, otherwise return invalid signature

### Challenge Analysis

After reading the server code and verifying that the signing and verifying implementation is sound we notice that two things are different from standard DSA; the hash function, and the nonce generation. Specifically, the generated nonces are not _random enough_. They are given by $k_i = H(m_i) + \text{padding} + i$, where $\text{padding}$ is some random number that is fixed across both of the signings that we have access to.

#### Bad Nonces in DSA

Before we proceed, we look at how detrimental bad nonces are in DSA. Given two signatures $(r_1, s_1)$ and $(r_2, s_2)$ (for messages $m_1$ and $m_2$) signed by a single private key $x$ and related nonces $k_1$ and $k_2 = f(k_1)$ (for some known linear function $f$), we can recover $x$. From step 3 of the signing procedure, we have the relations

$$
\begin{aligned}
\begin{cases}
    s_1 k_1 &\equiv H(m_1) + x r_1 \pmod q \\
    s_2 f(k_1) &\equiv H(m_2) + x r_2 \pmod q \\
\end{cases}
\end{aligned}
$$

This is a linear system in the unknowns $k_1$ and $x$, and can therefore be easily solved.

#### Solving the Challenge

Now that we have the motivation, we notice that if we choose our two messages $m_1$ and $m_2$ such that we know the relation between the two nonces that are derived from these messages, we can recover the secret signing key and forge the required signature. Peculiarly, the custom hash function being used is based on SHA1 which is known to be broken. We can find 640-byte collisions from [here](https://sha-mbles.github.io/). Notice that if the hashes for two messages are the same, then the nonces will differ by 1. This puts us in the situation of the previous section, so we can recover the secret signing key.

To actually solve the system of equations found in the previous section, we make use of Sage's convenient methods for doing so. Of course, we could rearrange the terms by hand to isolate $x$, but that is annoying and error prone. It also becomes a lot harder when we have more than two equations. There are two methods I like to use. One is by Gröbner basis techniques, and another is by taking resultants.

**Gröbner basis**: We construct the two polynomials and find the variety of the ideal generated by them. The variety is simply the set of solutions satisfying both polynomials. Under the hood, it is computed by first finding a Gröbner basis of the ideal, which can be thought of as a new set of polynomials that generate the same ideal, but with nicer properties that make it easier to find the solutions of the system.

```py
R.<k,x> = GF(q)[]
f1 = s1*k - h1 - x*r1
f2 = s2*(k+1) - h2 - x*r2
V = Ideal([f1, f2]).variety()
k, x = V[0][k], V[0][x]
```

**Resultants**: We construct the two polynomials as before and eliminate a variable (in this case `k`), by taking the resultant of the two polynomials. Sage has inbuilt `resultant` methods for polynomials over the integers, but for polynomials over finite integer rings, it seems to not work. We can define our own resultant function from its definition as the determinant of the Sylvester matrix of the two polynomials. Once we eliminate one variable, we are left with a polynomial in the other variable (in this case `x`). Sage has an inbuilt method to find roots of univariate polynomials modulo prime integers, so we can use that to recover `x`.

```py
from sage.matrix.matrix2 import Matrix 
def resultant(f1, f2, var):
    return Matrix.determinant(f1.sylvester_matrix(f2, var))
    
R.<k,x> = GF(q)[]
f1 = s1*k - h1 - x*r1
f2 = s2*(k+1) - h2 - x*r2
x = resultant(f1, f2, k).univariate_polynomial().roots()[0][0]
```

Full solve script:

```py
from pwn import *
from hashlib import sha1

messageA = open('./messageA', 'rb').read()
messageB = open('./messageB', 'rb').read()

assert sha1(messageA).digest() == sha1(messageB).digest()
assert messageA != messageB

conn = remote('mc.ax', 31538)
print(conn.recvline().decode())
conn.sendline(input('pow: '))
conn.recvuntil('solution: ')

p = int(conn.recvline().decode())
q = int(conn.recvline().decode())
g = int(conn.recvline().decode())
y = int(conn.recvline().decode())

conn.recvline()
conn.sendline(messageA.hex())
h1 = int(conn.recvline().decode())
r1 = int(conn.recvline().decode())
s1 = int(conn.recvline().decode())

conn.recvline()
conn.sendline(messageB.hex())
h2 = int(conn.recvline().decode())
r2 = int(conn.recvline().decode())
s2 = int(conn.recvline().decode())

R.<k,x> = GF(q)[]
f1 = s1*k - h1 - x*r1
f2 = s2*(k+1) - h2 - x*r2
# V = Ideal([f1, f2]).variety()
# k, x = V[0][k], V[0][x]

from sage.matrix.matrix2 import Matrix 
def resultant(f1, f2, var):
    return Matrix.determinant(f1.sylvester_matrix(f2, var))
x = resultant(f1, f2, k).univariate_polynomial().roots()[0][0]

conn.recvline()
conn.recvline()
conn.recvline()

h = int(conn.recvline().decode().split(':')[1])
k = int(1337)
r = pow(g, k, p) % q
s = (pow(k, q-2, q) * (h + x * r)) % q
conn.sendline(str(r))
conn.sendline(str(s))

print(conn.recvline().decode())
```

Flag: `flag{here_it_is_a8036d2f57ec7cecf8acc2fe6d330a71}`
