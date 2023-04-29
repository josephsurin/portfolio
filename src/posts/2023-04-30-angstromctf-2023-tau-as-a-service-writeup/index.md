---
path: /posts/2023-04-30-angstromctf-2023-tau-as-a-service-writeup
title: ångstromCTF 2023 - tau as a service
date: 2023-04-30
tags: ctf,writeup,crypto
---

# tau as a service

> Who needs powers-of-tau ceremonies when you have [τaas](https://files.actf.co/0bdf867857490d6fb99e0d1b7c8ebf2edf15c7356ee8526059b9687c6c094f64/taas.py)?
> 
> `nc challs.actf.co 32500`
>
> Author: defund

`taas.py`:

```py
#!/usr/local/bin/python

from blspy import PrivateKey as Scalar

# order of curve
n = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

with open('flag.txt', 'rb') as f:
    tau = int.from_bytes(f.read().strip(), 'big')
    assert tau < n

while True:
    d = int(input('gimme the power: '))
    assert 0 < d < n
    B = Scalar.from_bytes(pow(tau, d, n).to_bytes(32, 'big')).get_g1()
    print(B)
```

# Solution

The handout source code for this challenge is quite small (only 16 lines!). It uses the [blspy](https://github.com/Chia-Network/bls-signatures) library which is a library that implements BLS12-381 signatures. This library is written primarily in C++, but there is also a [pure Python implementation](https://github.com/Chia-Network/bls-signatures/tree/main/python-impl) which has a similar API to the Python bindings and is a bit easier to read.

The first step is understanding what the server is doing. It reads the flag into the `tau` variable as an integer, then takes our input between `0` and `n` and gives us the value of `PrivateKey.from_bytes(pow(tau, d, n).to_bytes(32, 'big')).get_g1()`. We can do this as many times as we want. In the pure Python implementation of blspy, we can see the `PrivateKey` class implemented [here](https://github.com/Chia-Network/bls-signatures/blob/1feb2181a7e07904df86abac991a05124f69bab9/python-impl/private_key.py#L7). It is meant to be instantiated with an integer (the private key) smaller than `n`. The [`from_bytes`](https://github.com/Chia-Network/bls-signatures/blob/1feb2181a7e07904df86abac991a05124f69bab9/python-impl/private_key.py#L18-L20) method essentially just takes the input bytes argument, converts it to an integer and then instantiates the class with it. The [`get_g1`](https://github.com/Chia-Network/bls-signatures/blob/1feb2181a7e07904df86abac991a05124f69bab9/python-impl/private_key.py#L35-L36) method simply returns the private key multiplied by a constant point [`G1Generator`](https://github.com/Chia-Network/bls-signatures/blob/1feb2181a7e07904df86abac991a05124f69bab9/python-impl/ec.py#L477-L478). The last thing is how this result is given to us as a string. There is a slight difference here between the pure Python implementation and the Python bindings for the native library, but the hex string we are eventually given is the result of calling the [`point_to_bytes`](https://github.com/Chia-Network/bls-signatures/blob/1feb2181a7e07904df86abac991a05124f69bab9/python-impl/ec.py#L243-L265) function on the point; it more or less serialises the point by taking the x coordinate and using the unused top bits for things like the sign of the y coordinate.

In summary, the server is essentially an oracle $\mathcal{O}(d)$ which gives us the value of $[\tau^d]g$ for an input $0 < d < n$.

It turns out that a deep understanding of BLS12-381 isn't really required to solve this challenge, but some [background reading](https://hackmd.io/@benjaminion/bls12-381) definitely won't hurt. The basic idea is that there are two main groups (elliptic curves) we work with when using BLS12-381. These groups are called $G_1$ and $G_2$ and both have order $n$. In the challenge $g$ is a generator for the group $G_1$ which we work with exclusively. The group $G_1$ is the order-$n$ subgroup of $E(\mathbb{F}_p): y^2 = x^3 + 4$, which is more or less just a regular old elliptic curve. The main point being, is that this challenge doesn't actually have too much to do with the technical details of BLS12-381 itself. However, this isn't super obvious when you first look at the challenge, and searching up things related to BLS12-381 helps a lot. It may even lead you to [this post](https://ethresear.ch/t/cheons-attack-and-its-effect-on-the-security-of-big-trusted-setups/6692) or [this paper](http://www.math.snu.ac.kr/~jhcheon/publications/2010/StrongDH_JoC_Final2.pdf) which describes an efficient attack that precisely fits the setting of the challenge.

We are most interested in Corollary 1 of the Cheon paper. It states (rewritten in additive notation):

**Corollary 1 ([Cheon](http://www.math.snu.ac.kr/~jhcheon/publications/2010/StrongDH_JoC_Final2.pdf)).** Let $G$ be an abelian group of order $n$ with a generator $g$. Suppose that a factorisation of $n-1$ is given as $n - 1 = d_1 d_2 \cdots d_t$ for pairwise relatively prime $d_i$. If $g$ and $g_{d_i} =[\tau^{\frac{n-1}{d_i}}]g$ for $1 \leq i \leq t$ are given, then $\tau$ can be computed using
$$
O \left (\sum_{i=1}^t \sqrt{d_i} \right )
$$
group exponentiations and at most $\max_{1 \leq i \leq t} \lceil \sqrt{d_i} \rceil$ storage of elements of $G$.

The idea (following from Cheon's proof) is as follows:

Let $\tau = \zeta^k$ for a generator $\zeta$ of $(\mathbb{Z}/n\mathbb{Z})^\times$ and let $\zeta_{d_i} = \zeta^{\frac{n-1}{d_i}}$ be a generator of the order $d_i$ subgroup in $(\mathbb{Z}/n\mathbb{Z})^\times$. Note that $\tau^{\frac{n-1}{d_i}} \in \langle \zeta_{d_i} \rangle$ and so for some integer $k_i < d_i$, we have $\tau^{\frac{n-1}{d_i}} = \zeta_{d_i}^{k_i}$. It therefore follows that

$$
[\tau^{\frac{n-1}{d_i}}]g = g_{d_i} = [\zeta_{d_i}^{k_i}]g
$$

The idea from the baby-step giant-step algorithm is to then write $k_i$ as $k_i = u_i + \lceil \sqrt{d_i} \rceil v_i$ where $0 \leq u_i, v_i < \lceil \sqrt{d_i} \rceil$. This gives us

$$
\begin{aligned}
    g_{d_i} &= [\zeta_{d_i}^{u_i + \lceil \sqrt{d_i} \rceil v_i}]g \\
    \implies [\zeta_{d_i}^{-u_i}]g_{d_i} &= [\zeta_{d_i}^{\lceil \sqrt{d_i} \rceil v_i}]g \\
\end{aligned}
$$

We can then use a meet-in-the-middle approach and compute a lookup table of the left-hand side values (of which there are $\lceil \sqrt{d_i} \rceil$ candidates), followed by computing candidates for the right-hand side value (of which there are again $\lceil \sqrt{d_i} \rceil$ candidates) and when a match is found, we've found the correct $u_i$ and $v_i$ values from which $k_i$ can be recovered. Once we have the $k_i$ values (which satisfy $k_i = k \pmod{d_i}$), we can combine them using the Chinese Remainder Theorem to recover the full value of $k$ and finally recover $\tau$ by computing $\zeta^k$.

The complexity is $O(\sqrt{d_i})$, so we need the largest factor of $n-1$ to be small. Conveniently, the order of $(\mathbb{Z}/n\mathbb{Z})^\times$ is quite smooth:

$$
n - 1 =  2^{32} \times 3 \times 11 \times 19 \times 10177 \times 125527 \times 859267 \times 906349^2 \\
        \ \times \ 2508409 \times 2529403 \times 52437899 \times 254760293^2
$$

However, the $254760293^2$ term is 56 bits, meaning we would still require around $2^{28}$ elliptic curve operations. This is feasible, but would end up taking up to thee full days with a naive implementation.

Fortunately, we can use ideas from the Pohlig-Hellman algorithm to reduce the complexity to $O(e_i \sqrt{p_i})$, where $d_i = p_i^{e_i}$. For simplicity, we will just treat the case when $e_i = 2$ as all the others can be solved quickly enough using the naive baby-step giant-step approach above.

As above, we have

$$
g_{p_i^2} = [\zeta_{p_i^2}^{k_i}]g
$$

for some integer $k_i < p_i^2$. We can write $k_i = \ell_{i,1} + p_i \ell_{i,2}$ for integers $0 \leq \ell_{i, 1}, \ell_{i, 2} < p_i$. We will argue that $\tau^{\frac{n-1}{p_i}} = \zeta_{p_i}^{\ell_{i, 1}}$ and hence that

$$
g_{p_i} = [\zeta_{p_i}^{\ell_{i,1}}]g
$$

We have

$$
\begin{aligned}
    \tau^{\frac{n-1}{p_i^2}} &= \zeta_{p_i^2}^{k_i} \\
    \implies \tau^{\frac{n-1}{p_i}} &= \zeta_{p_i^2}^{p_i k_i} \\
                                    &= \zeta^{\frac{n-1}{p_i^2}(p_i k_i)} \\
                                    &= \zeta_{p_i}^{k_i} \\
                                    &= \zeta_{p_i}^{\ell_{i,1} + p_i \ell_{i,2}} \\
                                    &= \zeta_{p_i}^{\ell_{i,1}} \\
\end{aligned}
$$

Where the last line follows because the order of $\zeta_{p_i}$ is $p_i$. We can recover $\ell_{i,1}$ in time $O(\sqrt{p_i})$ given $g_{p_i}$ using the baby-step giant-step approach.

Then

$$
\begin{aligned}
    g_{p_i^2} &= [\zeta_{p_i^2}^{k_i}]g \\
                          &= [\zeta_{p_i^2}^{\ell_{i,1} + p_i \ell_{i,2}}]g \\
                          &= [\zeta^{\frac{n-1}{p_i^2}(\ell_{i,1} + p_i \ell_{i,2})}]g \\
                          &= [\zeta^{\frac{n-1}{p_i^2}\ell_{i,1} + \frac{n-1}{p_i}\ell_{i,2}}]g \\
                          &= [\zeta^{\frac{n-1}{p_i^2}\ell_{i,1}} \zeta^{\frac{n-1}{p_i}\ell_{i,2}}]g \\
    \implies [\zeta^{-\frac{n-1}{p_i^2}\ell_{i,1}} ]g_{p_i^2} &= [\zeta^{\frac{n-1}{p_i}\ell_{i,2}}]g \\
    \implies [\zeta_{p_i^2}^{-\ell_{i,1}} ]g_{p_i^2} &= [\zeta_{p_i}^{\ell_{i,2}}]g \\
\end{aligned}
$$

Again, $\ell_{i,2}$ can be recovered in time $O(\sqrt{p_i})$ using the baby-step giant-step approach. After obtaining both $\ell_{i,1}$ and $\ell_{i,2}$ we can recover $k_i$ by computing $k_i = \ell_{i,1} + p_i \ell_{i,2}$.

```py
from pwn import *
from tqdm import tqdm

def bsgs(p, g_p, g1):
    lut = {}
    z_i = zeta^((n-1)//p)
    for ui in tqdm(range(ceil(sqrt(p)))):
        z = pow(z_i, -ui, n-1)
        lhs = z * g_p
        lut[str(lhs)] = ui
    for vi in tqdm(range(ceil(sqrt(p)))):
        z = pow(z_i, ceil(sqrt(p)) * vi, n-1)
        rhs = z * g1
        if str(rhs) in lut:
            return lut[str(rhs)] + ceil(sqrt(p)) * vi

def find_ki(d_i, g_d_i):
    return bsgs(d_i, g_d_i, g1)

def find_ki2(p, g_p, g_p2):
    l1 = bsgs(p, g_p, g1)
    l2 = bsgs(p, pow(zeta^((n-1)//p^2), -l1, n-1) * g_p2, g1)
    return l1 + p*l2

def deserialise_point(point_str):
    b = bytes.fromhex(point_str)
    m_byte = b[0] & 0xE0
    buf = bytes([b[0] & 0x1F]) + b[1:]
    x = int.from_bytes(buf, 'big') % p
    s_bit = (m_byte & 0x20) >> 5
    y = E1.lift_x(x)[1]
    if (s_bit == 0 and y > (p-1)//2) or (s_bit == 1 and y < (p-1)//2):
        y *= -1
    return E1((x, y))

p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
F = GF(p)
a = F(0x00)
b = F(0x04)
E1 = EllipticCurve(F, (a, b))
g1 = E1(0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB, 0x08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1)
h = 0x396C8C005555E1568C00AAAB0000AAAB
n = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
E1.set_order(n * h)
zeta = GF(n).multiplicative_generator()

def oracle(d):
    conn.sendlineafter(b'gimme the power: ', str(d).encode())
    return conn.recvline().decode().strip()

data = []
conn = remote('challs.actf.co', 32500)
print('collecting data from oracle...')
for p_i, e_i in tqdm(factor(n - 1)):
    d_i = p_i^e_i
    if e_i == 2:
        g_p = oracle((n-1)//p_i)
        g_p2 = oracle((n-1)//p_i^2)
        data.append((p_i, g_p, g_p2))
    elif e_i == 32:
        g_p = oracle((n-1)//p_i^16)
        g_p2 = oracle((n-1)//p_i^32)
        data.append((p_i^16, g_p, g_p2))
    else:
        g_di = oracle((n-1)//d_i)
        data.append((d_i, g_di))

K = []
M = []
for dat in sorted(data):
    print(f'solving dlog in subgroup of order {dat[0]}')
    if len(dat) == 2:
        d_i, g_di = dat
        g_di = deserialise_point(g_di)
        k_i = find_ki(d_i, g_di)
        K.append(k_i)
        M.append(d_i)
    else:
        p_i, g_p, g_p2 = dat
        g_p = deserialise_point(g_p)
        g_p2 = deserialise_point(g_p2)
        k_i = find_ki2(p_i, g_p, g_p2)
        K.append(k_i)
        M.append(p_i^2)
    print(f'{dat[0]}: k_i = {k_i}')
k = crt(K, M)
flag = int(zeta^k).to_bytes(32, 'big')
print(flag.decode())

# actf{w3_g0t_the_p0wer_tod0_th4t}
```
