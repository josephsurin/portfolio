---
path: /posts/2020-08-24-googlectf-2020-writeups
title: Google CTF 2020 Writeups
date: 2020-08-24
tags: ctf,infosec,writeup,crypto
---

Difficult!

- crypto
    - [chunk norris](#chunk-norris)

---

# chunk norris <a name="chunk-norris"></a>

### crypto (easy)

> Chunk Norris is black belt in fast random number generation.

```python
#!/usr/bin/python3 -u

import random
from Crypto.Util.number import *
import gmpy2

a = 0xe64a5f84e2762be5
chunk_size = 64

def gen_prime(bits):
  s = random.getrandbits(chunk_size)

  while True:
    s |= 0xc000000000000001
    p = 0
    for _ in range(bits // chunk_size):
      p = (p << chunk_size) + s
      s = a * s % 2**chunk_size
    if gmpy2.is_prime(p):
      return p

n = gen_prime(1024) * gen_prime(1024)
e = 65537
flag = open("flag.txt", "rb").read()
print('n =', hex(n))
print('e =', hex(e))
print('c =', hex(pow(bytes_to_long(flag), e, n)))
```

## Solution

We can write

$$
p = 2^{64 \cdot 15} s_0 + 2^{64 \cdot 14} s_1 + \cdots + 2^{64} s_{14} + s_{15}
$$

and

$$
q = 2^{64 \cdot 15} t_0 + 2^{64 \cdot 14} t_1 + \cdots + 2^{64} t_{14} + t_{15}
$$

where the $s_i$ and $t_i$ are related by

$$
s_i \equiv as_{i-1} \pmod {2^{64}} \qquad t_i \equiv at_{i-1} \pmod {2^{64}}
$$

So

$$
n = 2^{2 \cdot 64 \cdot 15} s_0 t_0 + \cdots + 2^{64} (s_{14}t_{15} + t_{14}s_{15}) + s_{15} t_{15}
$$

The goal is to recover any of the $s_i$ or $t_i$ as each chunk is generated from an LCG so any output will be easily recovered given at least one output.

For simplicity, we'll write $s = s_{15}$ and $t = t_{15}$. Then, $s_{14} = a^{-1} s$ and $t_{14} = a^{-1} t$. Therefore, reducing $n$ modulo $2^{128}$ we get

$$
\begin{aligned} n &\equiv 2^{64} (2a^{-1}st) + st \pmod {2^{128}} \\ &\equiv st(2^{65}a^{-1} + 1) \pmod {2^{128}} \end{aligned}
$$

And since $(2^{65}a^{-1} + 1)$ is odd, it has a multiplicative inverse modulo $2^{128}$.

$$
st \equiv n(2^{65}a^{-1} + 1)^{-1} \pmod{ 2^{128} }
$$

We can compute the right hand side, and factoring it gives us possible factors for $s$ and $t$. Since $s$ and $t$ aren't prime, we'll have to play around a bit manually to see which factors are for $s$ and which are for $t$. This is quite easy to do; we just try to make $s$ and $t$ have roughly the same bit length.

After recovering $s$ and $t$, we can easily recover all of $p$ and $q$ by reversing the LCG and decrypt the textbook RSA.

**Solve script:**

```python
from Crypto.Util.number import long_to_bytes

a = 0xe64a5f84e2762be5
ainv = inverse_mod(a, 2^64)
n = 0xab802dca026b18251449baece42ba2162bf1f8f5dda60da5f8baef3e5dd49d155c1701a21c2bd5dfee142fd3a240f429878c8d4402f5c4c7f4bc630c74a4d263db3674669a18c9a7f5018c2f32cb4732acf448c95de86fcd6f312287cebff378125f12458932722ca2f1a891f319ec672da65ea03d0e74e7b601a04435598e2994423362ec605ef5968456970cb367f6b6e55f9d713d82f89aca0b633e7643ddb0ec263dc29f0946cfc28ccbf8e65c2da1b67b18a3fbc8cee3305a25841dfa31990f9aab219c85a2149e51dff2ab7e0989a50d988ca9ccdce34892eb27686fa985f96061620e6902e42bdd00d2768b14a9eb39b3feee51e80273d3d4255f6b19
e = 0x10001
c = 0x6a12d56e26e460f456102c83c68b5cf355b2e57d5b176b32658d07619ce8e542d927bbea12fb8f90d7a1922fe68077af0f3794bfd26e7d560031c7c9238198685ad9ef1ac1966da39936b33c7bb00bdb13bec27b23f87028e99fdea0fbee4df721fd487d491e9d3087e986a79106f9d6f5431522270200c5d545d19df446dee6baa3051be6332ad7e4e6f44260b1594ec8a588c0450bcc8f23abb0121bcabf7551fd0ec11cd61c55ea89ae5d9bcc91f46b39d84f808562a42bb87a8854373b234e71fe6688021672c271c22aad0887304f7dd2b5f77136271a571591c48f438e6f1c08ed65d0088da562e0d8ae2dadd1234e72a40141429f5746d2d41452d916

st = n * inverse_mod(2^65 * inverse_mod(a, 2^64) + 1, 2^128) % 2^128
print(factor(st))

s = 13 * 167541865434116759
t = 11 * 109 * 223 * 1290533 * 4608287

def gen_backward_prime(s):
    p = s
    for i in range(1,16):
        s = ainv * s % 2^64
        p += s * 2^(64*i)
    return p

p, q = gen_backward_prime(s), gen_backward_prime(t)
d = inverse_mod(e, (p-1)*(q-1))
flag = pow(c,d,n)
print(long_to_bytes(flag).decode())
```

Flag: `CTF{__donald_knuths_lcg_would_be_better_well_i_dont_think_s0__}`
