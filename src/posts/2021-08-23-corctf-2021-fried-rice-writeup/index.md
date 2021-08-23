---
path: /posts/2021-08-23-corctf-2021-fried-rice-writeup
title: corCTF 2021 - fried rice
date: 2021-08-23
tags: ctf,infosec,writeup,crypto
---

corCTF was fun! 🛹🐶 finished in 8th and we managed to clear all the crypto challenges.

# fried rice (6 solves)

> Kind of hungry... guess I'll make some fried rice.
>
> NOTE: The server has a time limit of 5 minutes.
>
> `nc crypto.be.ax 6003`

```py
from random import shuffle, randrange, randint
from os import urandom
from Crypto.Util.number import getPrime, getStrongPrime, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from private import flag
import sys

class RNG:
    def __init__(self, seed, a, b):
        self.state = seed
        self.a = a
        self.b = b
        print('a:', a)
        print('b:', b)

    def nextbits(self, bitlen):
        out = 0
        for _ in range(bitlen):
            out <<= 1
            self.state = self.a * self.state + b
            bit = int(sum(self.state[i] for i in range(7)))
            out += bit
        return out

def get_params(rng, bitlen):
    p = next_prime((1 << (bitlen - 1)) | rng.nextbits(bitlen))
    q = next_prime((1 << (bitlen - 1)) | rng.nextbits(bitlen))
    N = p * q
    return N, p, q

LIMIT = 26
P.<x> = PolynomialRing(GF(2))
F.<x> = P.quo(x^128 + x^7 + x^2 + x + 1)
key, a, b = [F.random_element() for _ in range(3)]
bytekey = long_to_bytes(int(''.join(list(map(str, key.list()))), 2))
iv = os.urandom(16)
cipher = AES.new(bytekey, AES.MODE_CBC, IV=iv)
rng = RNG(key, a, b)
N, p, q = get_params(rng, 512)
if randint(0, 1):
    p, q = q, p
e = 65537
d = inverse_mod(e, (p-1)*(q-1))
dp = d % (p-1)
r = getStrongPrime(1024)
g = randrange(2, r)
print('iv:', iv.hex())
print('N:', N)
print('e:', e)
print('g:', g)
print('r:', r)
print('encrypted flag:', cipher.encrypt(pad(flag, 16)).hex())
print()
print("now, let's cook some fried rice!")
for _ in range(LIMIT):
    sys.stdout.flush()
    m = int(input('add something in(in hex)> '), 16)
    dp ^^= m
    print('flip!', pow(g, dp, r))
print("it's done. enjoy your fried rice!")
```

The server generates a random 128 bit key and uses it to encrypt the flag with AES. It also implements a custom RNG and uses it with the same 128 bit key as the seed. The server then creates an RSA key using the RNG to generate the primes $p$ and $q$. It takes $e = 65537$ and computes $d \equiv e^{-1} \pmod{(p-1)(q-1)}$ as well as $d_p \equiv d \pmod{p-1}$. Finally, it generates a random _strong_ 1024 bit prime $r$ and a generator $2 \leq g < r$. We are given $N = pq$, $e$, $g$, $r$ and the encrypted flag.

The server then allows us 26 queries, each in which we can modify the value of $d_p$ by XORing it with a value of our choice; we give it an input $m$ and it sets $d_p \leftarrow d_p \oplus m$ and gives us the result of $g^{d_p} \mod r$.

## Solution

The flag is encrypted with the key used as the RNG's seed, so to be able to decrypt the flag, we'll need to crack the RNG to recover the seed. To do this, recovering $d_p$ using the bit flip queries seems like the only possible approach. For now, we will focus on recovering $d_p$ and talk about the RNG later.

### Recovering $d_p$

To preface this section as a disclaimer, I had originally thought that $d_p$ was 1024 bits (small brain moment) so my approach kept that in mind. However, the approach works regardless of the secret size. The first thing we noticed was that $r$ is generated as a _strong_ prime, and not necessarily a _safe_ prime (which is of the form $2q + 1$ for prime $q$). This means that it is likely for $r-1$ to have some small factors, which will be very useful for solving the DLP for up to a certain bound.

#### Server Interaction

Because we only have 26 queries, we need to reconnect until we get a good $r$ such that $r-1$ has small factors (where small means we are happy to solve a DLP of that size) totalling around 41 bits (or so I thought, but for a 512 bit secret we only need around 21 bits). We call this value the `CHUNK_SIZE` and it can be anything depending on the factors $r-1$. We will send values of the form $2^{i \times \mathit{chunk\_size}} \cdot (2^{\mathit{chunk\_size}} - 1)$ (which is a bit string of `CHUNK_SIZE` ones, left shifted by $i \times \mathit{chunk\_size}$). We will expand on how to use this later.

The following script deals with the server interactions, printing out $r$ for us so we can check its small factors and determine the chunk size to use (we did this manually with Alpertron...), and performing the queries to get all the bit flipped values:

```py
import os
os.environ['PWNLIB_NOTERM'] = 'True'
from pwn import *
from parse import parse

def do_flip(b):
    conn.sendlineafter('> ', hex(b))
    out = list(parse('flip! {:d}\n', conn.recvline().decode()))[0]
    return out

P.<x> = PolynomialRing(GF(2))
F.<x> = P.quo(x^128 + x^7 + x^2 + x + 1)

conn = remote('crypto.be.ax', 6003)

a = F(conn.recvline().decode().strip().split('a: ')[1])
b = F(conn.recvline().decode().strip().split('b: ')[1])
iv = bytes.fromhex(conn.recvline().decode().split('iv: ')[1])
N = list(parse('N: {:d}\n', conn.recvline().decode()))[0]
e = list(parse('e: {:d}\n', conn.recvline().decode()))[0]
g = list(parse('g: {:d}\n', conn.recvline().decode()))[0]
r = list(parse('r: {:d}\n', conn.recvline().decode()))[0]
flag_enc = bytes.fromhex(conn.recvline().decode().split('encrypted flag: ')[1])

print(f'{a = }')
print(f'{b = }')
print(f'iv = "{iv.hex()}"')
print(f'{N = }')
print(f'{e = }')
print(f'{g = }')
print(f'{r = }')
print(f'flag_enc = "{flag_enc.hex()}"')

gd = do_flip(0)
flips = []
# use alpertron to get small factors and determine a chunk size...
CHUNK_SIZE = int(input('chunk size? '))
for i in range(25):
    bf = 2^(CHUNK_SIZE*i) * (2^CHUNK_SIZE - 1)
    t = do_flip(bf)
    flips.append(t)

print(f'{gd = }')
print(f'{flips = }')
```

We are left with all the values we need and can solve the rest of the challenge offline. We got lucky and quickly found an $r$ with chunk size 75 bits, well more than what is required for finding a 1024 bit secret.

#### Recovering $d_p$ one chunk at a time

Our very first query was used to get the value of $g^{d_p}$ so we treat this specially and exclude it when we talk about "flip" queries.

Let $b = 2^{\mathit{chunk\_size}} - 1$. In the first flip query, we sent $b$ and received $g^{d_p \oplus b}$. In the query after that, we sent $2^{\mathit{chunk\_size}} \cdot b$ and received $g^{d_p \oplus b \oplus (2^{\mathit{chunk\_size}} \cdot b)}$. In general, the $i$th (starting from $i = 0$) flip query gives us

$$
g^{d_p \oplus b \oplus \cdots \oplus (2^{i \times \mathit{chunk\_size}} \cdot b)}
$$

Now, a common trick when working with XOR is to write it as an addition (where we obviously don't know what is being added, but we know what it is bounded by). So, we write the value of the $i$th flip query as

$$
g^{d_p + b_0 + \cdots + (2^{i \times \mathit{chunk\_size}} \cdot b_i)}
$$

where $|b_i| < 2^{\mathit{chunk\_size}}$. Now, we see that the first flip query gives us

$$
g^{d_p + b_0} = g^{d_p} g^{b_0}
$$

and since we know $g^{d_p}$ we can simply divide this value by it to get $g^{b_0}$. Since the bit length of $b_0$ is the same as the chunk size, we can easily solve for it by solving the DLP over the small factors of $r-1$. The next query gives us

$$
g^{d_p + b_0 + 2^{\mathit{chunk\_size}} \cdot b_1} = g^{d_p + b_0} g^{2^{\mathit{chunk\_size}} \cdot b_1}
$$

and dividing by $g^{d_p + b_0}$ (which we actually have from the first flip query), we get

$$
g^{2^{\mathit{chunk\_size}} \cdot b_1} = \left ( g^{2^{\mathit{chunk\_size}}} \right )^{b_1}
$$

Again, $b_1$ is "small" so we can solve this DLP (with base $g^{2^{\mathit{chunk\_size}}}$). We can repeat this process to recover all the $b_i$.

We aren't done yet; we need to account for the fact that $b_i$ may be negative. When we write $x \oplus b = x + b_i$, we can't tell whether $b_i$ is positive or negative. As far as I can tell, this means we will have two candidates for the actual bits of $d_p$ per chunk as we shall see.

Note that since $b$ is a bit string of all ones, then $x \oplus b = b - x$.

Now, let $x$ be the chunk of $d_p$ bits we are interested in finding. Suppose $x \oplus b = x - c_1$ where $c_1 \geq 0$. Then, we have $x \oplus b = b - x = x - c_1$ which implies $x = (b + c_1)/2$.

On the other hand, suppose instead that $x \oplus b = x + c_2$ where $c_2 > 0$. Then, we have $x \oplus b = b - x = x + c_2$ which implies $x = (b - c_2)/2$.

We get the value of $c_1$ by solving the DLP with a base of $g^{2^{- i \times \mathit{chunk\_size}}}$ and we get the value of $c_2$ by solving the DLP with a base of $g^{2^{i \times \mathit{chunk\_size}}}$.

Since we have two candidates for each chunk of $d_p$ bits, we will require an extra $2^{\mathit{num\_chunks}}$ exhaust to test each combination of candidates. We can verify the correct candidate $d'$ by checking that $g^{d'} = g^d$.

```py
from tqdm import tqdm

P.<x> = PolynomialRing(GF(2))
F.<x> = P.quo(x^128 + x^7 + x^2 + x + 1)
load('./data75.sage')
Fr = GF(r)
g = Fr(g)

CHUNK_SIZE = 75

def my_bsgs(a, b, bounds):
    lb, ub = bounds
    if lb < 0 or ub < lb:
        raise ValueError("bsgs() requires 0<=lb<=ub")
    if a == (0, 0) and not b == (0, 0):
        raise ValueError("No solution in bsgs()")
    ran = 1 + ub - lb
    c = b^-1 * a^lb
    if ran < 30:
        d = c
        for i0 in range(ran):
            i = lb + i0
            if d.is_one():
                return ZZ(i)
            d = a * d
        raise ValueError("No solution in bsgs()")
    m = ran.isqrt() + 1
    table = dict()
    d = c
    for i0 in xsrange(m):
        i = lb + i0
        if d.is_one():
            return ZZ(i)
        table[d] = i
        d = a * d
    c = c * d^-1
    d = Fr(1)
    for i in xsrange(m):
        j = table.get(d)
        if j is not None:
            return ZZ(i * m + j)
        d = c * d
    raise ValueError("Log of %s to the base %s does not exist in %s." % (b, a, bounds))

def solve_small_dlog(g, h):
    r_facs = [71,281,1830761873,5588764697]
    K = []
    for pi in r_facs:
        qi = int((r-1)//pi)
        gi = pow(g, qi, r)
        hi = pow(h, qi, r)
        j = my_bsgs(gi, hi, bounds=(0,pi))
        K.append(j)
    return crt(K, r_facs)

dp_cands = []
for i, f in tqdm(list(enumerate(flips))):
    if i == 0:
        h = Fr(f) / Fr(gd)
    else:
        h = Fr(f) / Fr(flips[i-1])
    c1 = solve_small_dlog(pow(g, -2^(CHUNK_SIZE*i), r), h)
    c2 = solve_small_dlog(pow(g, 2^(CHUNK_SIZE*i), r), h)
    b = 2^CHUNK_SIZE - 1
    d1 = abs((b + c1)//2)
    d2 = abs((b - c2)//2)
    if d2 == 0:
        break
    dp_cands.append((d1, d2))

for possible in tqdm(cartesian_product(dp_cands), total=int(2^len(dp_cands))):
    d_p = 0
    for kp in possible[::-1]:
        d_p <<= CHUNK_SIZE
        d_p += kp
    if pow(g, d_p, r) == gd:
        print('recovered d_p:', hex(d_p))
        break
```

This recovers $d_p$ in well under 10 seconds on my computer :)

### Recovering the RNG outputs

Now that we have $d_p$, we move on to our next goal; recover the outputs of the RNG. Since the RNG is used to generate $p$, this means we must recover $p$. Fortunately, this is very easy given that we have $d_p$:

$$
\begin{aligned}
    d_p &\equiv d \pmod{p-1} \\
        &\equiv e^{-1} \pmod{p-1} \\
    \implies d_p e &= 1 + t(p-1)
\end{aligned}
$$

where $t < e$ since otherwise the RHS would be too large. We can exhaust over $t$ and compute

$$
\gcd \left ( \frac{d_p e - 1}{t} + 1, N \right )
$$

to recover $p$. The actual outputs of the RNG start from the MSB of $p$.

### Cracking the RNG

We are now at the final stage! This part of the challenge is a bit similar to [phoenix from Aero CTF 2021](https://jsur.in/posts/2021-02-28-aero-ctf-2021-phoenix).

#### RNG construction

This subsection briefly outlines how the RNG works. We work in the polynomial quotient ring

$$
F = \mathbb{F}_2[x]/(x^{128} + x^7 + x^2 + x + 1)
$$

The RNG resembles an LCG; it has two parameters $a, b \in F$ and uses a seed $s \in F$ for the initial state. When we require a bit from the RNG, it updates the state by computing

$$
s \leftarrow as + b
$$

and then forms the output bit by taking the sum of the first 7 coefficients (which results in a single bit since addition is done in $\mathbb{F}_2$).

#### Recovering the seed

Of course, our ultimate goal is to recover the 128 bit seed polynomial $s$. To do this, we represent each coefficient of the state symbolically, and then _run_ the RNG on this state to get each output as an expression of the original 128 coefficients. To get this to work in Sage we construct a polynomial ring $K$ over $\mathbb{F}_2$ in the variables $k_0, k_1, \ldots, k_{127}$ and then construct another polynomial ring $R = K[x]/(x^{128} + x^7 + x^2 + x + 1)$. Since we represent each output as linear combinations of the initial seed coefficients, we can combine these with the RNG outputs to set up a linear system of equations which can be very easily solved.

```py
from tqdm import tqdm
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES

K = PolynomialRing(GF(2), [f'k{i}' for i in range(128)])
R.<x> = PolynomialRing(K, x).quo(x^128 + x^7 + x^2 + x + 1)

a = x^127 + x^125 + x^124 + x^123 + x^121 + x^117 + x^116 + x^112 + x^111 + x^109 + x^108 + x^104 + x^103 + x^98 + x^97 + x^95 + x^94 + x^92 + x^90 + x^89 + x^88 + x^86 + x^85 + x^82 + x^81 + x^79 + x^78 + x^74 + x^72 + x^70 + x^69 + x^67 + x^66 + x^65 + x^64 + x^62 + x^59 + x^58 + x^57 + x^52 + x^49 + x^47 + x^44 + x^43 + x^41 + x^39 + x^38 + x^37 + x^34 + x^33 + x^31 + x^29 + x^28 + x^26 + x^25 + x^24 + x^23 + x^21 + x^19 + x^17 + x^16 + x^11 + x^9 + x^8 + x^6 + x^4 + x^3 + x^2
b = x^127 + x^126 + x^125 + x^122 + x^117 + x^115 + x^114 + x^112 + x^111 + x^110 + x^108 + x^107 + x^106 + x^104 + x^103 + x^100 + x^99 + x^97 + x^94 + x^92 + x^89 + x^88 + x^87 + x^84 + x^81 + x^78 + x^74 + x^70 + x^68 + x^64 + x^62 + x^61 + x^58 + x^57 + x^55 + x^54 + x^53 + x^52 + x^49 + x^48 + x^45 + x^43 + x^42 + x^41 + x^40 + x^39 + x^34 + x^33 + x^32 + x^30 + x^29 + x^26 + x^24 + x^21 + x^19 + x^14 + x^11 + x^6 + x^3

p = 7607247116746482924111165833157763631664321066064556627638397511984109654170299609691369722141393187035143183523459578569674062704806743855511686527641711

def eqn_to_vec(eq):
    v = [0]*128
    for i in eq:
        v[i] = 1
    return v

def vec_to_poly(v):
    p = 0
    for i,c in enumerate(v):
        p += c*x^i
    return p

# p, q = q, p
rng_outputs = [1]
for i in range(510, 0, -1):
    rng_outputs.append((p >> i) & 1)

kvars = K.gens()
kvars_idx = { k:i for i,k in enumerate(kvars) }
state = sum(k*x^i for i,k in enumerate(kvars))
eqns = []
for i in tqdm(range(128)):
    state = state*a + b
    eq = sum(state[i] for i in range(7))
    g = [kvars_idx[k] for k in eq.variables()]
    eqns.append(eqn_to_vec(g) + [eq.constant_coefficient() - rng_outputs[i]])

A = Matrix(GF(2), eqns)
v = A.right_kernel_matrix()[0]
key = vec_to_poly(v[:128])
bytekey = long_to_bytes(int(''.join(list(map(str, key.list()))), 2))
iv = bytes.fromhex("bd60ccadcbf5306de0acba9ec710023b")
flag_enc = bytes.fromhex("7aea5391435fd35f820925801815413c8c7f4961aadeb58633c0d6e637d67664f40c242a3e26b1b5330ba77a1a705d45916bd934f7637b2cc4f5282584538945785ce6d08bd0303d8e4d5f0c5645e528")
cipher = AES.new(bytekey, AES.MODE_CBC, iv)
flag = cipher.decrypt(flag_enc)
print(unpad(flag, 16).decode())
```

Flag: `corctf{4nd_a_l1ttl3_bit_0f_gr3en_0ni0ns_on_t0p_dcca3160ef8135ea}`
